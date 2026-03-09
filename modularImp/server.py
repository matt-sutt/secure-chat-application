import websockets
import json
import base64
import time 
import logging
from typing import Dict, Tuple
import asyncio
import uuid
import hashlib
from collections import deque

# old import may not be necessasry
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# SOCP v1.3 library
from socp.modularImp.our_crytography import Cryptography

from socp.modularImp.constant import SERVER_HOST, SERVER_PORT, SERVER_ID, BUFFER_SIZE

from socp.modularImp.db import DatabaseManager
from socp.modularImp.introducerLoader import IntroducerLoader
from socp.modularImp.serverProtoHandler import ServerProtocolHandler
from socp.modularImp.envelope import Envelope
from socp.modularImp.EnvelopeType import EnvelopeType

# Defining our heatbeat
HEARTBEAT_INTERVAL = 15
HEARTBEAT_TIMEOUT = 45

from socp.modularImp.logging_config import setup_logging, module_logger
setup_logging()
SILENCE = 0
logger = module_logger(__name__, silence=bool(SILENCE))


# Turning off logs produced by python methods
logging.getLogger("asyncio").disabled = True
logging.getLogger("websockets").disabled = True
logging.getLogger("websockets.client").disabled = True
logging.getLogger("websockets.server").disabled = True
logging.getLogger("Database").disabled = True



class Server:
    def __init__(self,host: str, port: str):
        #these are server constants from constant.py
        self.host = host 
        self.port = port
        
        self.server_id = f"temp_{uuid.uuid4().hex[:8]}"  # e.g. temp_a1b2c3d4


        self.crypto = Cryptography()
        #Each server generate
        self.server_private_key, self.server_public_key= self.crypto.generate_rsa_keys()


        self.server_pub_b64 = self.crypto.export_public_key_b64url(self.server_public_key)

        # self.connected_clients: Dict[socket.socket, dict] = {}
        #Hooks to database and protocol handler
        self.db = DatabaseManager(f"{self.server_id}.db")
        self.server_proto_handler = ServerProtocolHandler(self)


        self.running = False #check if the server is running or not

        #Require In-Memory Tables
        self.servers = {} #{'server_id',server_info}
        self.servers_link = {} # {'server_id',Link (WebSocket stream wrapper)}
        self.server_addrs = {} #{'server_id',(host,port)} <- server_id with Advertise Address
        self.server_pubkeys = {} #{'server_id',public_key_PEM}

        self.user_pubkeys: Dict[str, str] = {}

        self.local_users = {} #{'user_id',Link (WebSocket stream wrapper)}
        self.user_location = {} #local | f"server_{id}""

        # Heartbeat logic (checking other servers are alive)
        self.server_last_seen: Dict[str, int] = {}
        self.started_server_at = int(time.time() * 1000)
        self.heartbeat = None
        self.enable_heartbeat = False

        logger.info("[%s] Server initialized on %s:%s", self.server_id, self.host, self.port)

        # se
        self.seen_ids: Dict[tuple, int] = {}
        self.seen_keep_for: int = 30_000 # keep for 30 seconds
        self.seen_max: int = 5000 # soft cap to prune map size


    # method to sign canonical JSON of payload with RSASSA-PSS(SHA-256), base64url(nopad)

    def sign_transport(self, envelope: Envelope):
        envelope.signature = self.crypto.sign_pss_b64(
            self.server_private_key,
            self.crypto.transport_sig_bytes(envelope.payload)
        )


    # Lifecycle 
    async def start(self):
        self.running = True
        logger.info("[%s] Starting WebSocket server at %s:%s", self.server_id, self.host, self.port)

        async with websockets.serve(self.handle_connection, self.host, self.port):
            if self.enable_heartbeat:
                self.heartbeat = asyncio.create_task(self.heartbeat_loop())

            logger.info("[%s] WebSocket server started, entering main loop.", self.server_id)

            try:
                await asyncio.Future() # Run forever
            finally:
                self.running = False
                if self.enable_heartbeat and self.heartbeat:
                    self.heartbeat.cancel()
                logger.info("[%s] Server stopped", self.server_id)

    # Peer/socket helpers
    def is_peer_socket(self, ws) -> bool:
        try:
            return ws in self.servers.values()
        except Exception:
            return False

    def _seen_key(self, envelope: 'Envelope') -> tuple:
        try:
            payload_bytes = self.crypto.transport_sig_bytes(envelope.payload or {})
        except Exception:
            payload_bytes = b"{}"
        p_hash = hashlib.sha256(payload_bytes).hexdigest()
        ts = int(getattr(envelope, 'ts', 0) or 0)
        sender = getattr(envelope, 'sender', None)
        receiver = getattr(envelope, 'receiver', None)
        return (ts, sender, receiver, p_hash)

    def seen_s2s_duplicate(self, envelope: 'Envelope') -> bool:
        """Return True if we've seen this server-delivered frame recently; else remember it."""
        try:
            key = self._seen_key(envelope)
        except Exception:
            return False
        now_ms = int(time.time() * 1000)
        prev = self.seen_ids.get(key)
        if prev is not None and (now_ms - prev) < self.seen_keep_for:
            return True
        # remember and prune occasionally
        self.seen_ids[key] = now_ms
        if len(self.seen_ids) > self.seen_max:
            cutoff = now_ms - self.seen_keep_for
            # prune old entries
            self.seen_ids = {k: v for k, v in self.seen_ids.items() if v >= cutoff}
        return False

    # Peer connectivity helpers
    async def connect_to_peer(self, sid: str, host: str, port: int):
        if sid == self.server_id:
            return False
        if sid in self.servers:
            return True
        uri = f"ws://{host}:{port}"
        try:
            ws = await websockets.connect(uri)
            self.servers[sid] = ws
            self.server_addrs[sid] = (host, port)
            logger.info("[%s] Connected to peer server %s at %s:%s", self.server_id, sid, host, port)
            asyncio.create_task(self.listen_to_peer(ws))
            # Optionally announce ourselves to this new peer
            await self.send_server_announce()
            # Send current local presence to the newly connected peer
            await self.send_presence_catchup_to_peer(sid)
            return True
        except Exception as e:
            logger.error("[%s] Failed to connect to peer %s at %s:%s: %s", self.server_id, sid, host, port, e, exc_info=True)
            return False

    async def ensure_peer_connection(self, sid: str, host: str, port: int):
        if sid not in self.servers:
            return await self.connect_to_peer(sid, host, port)
        return True

    # Send USER_ADVERTISE for all currently online local users to a specific peer
    async def send_presence_catchup_to_peer(self, peer_sid: str):
        try:
            ws = self.servers.get(peer_sid)
            if not ws:
                return
            for uid in list(self.local_users.keys()):
                pub = self.user_pubkeys.get(uid)
                if not pub:
                    continue
                payload = {
                    "user_id": uid,
                    "server_id": self.server_id,
                    "meta": {"pubkey_b64": pub},
                }
                env = Envelope(
                    EnvelopeType.USER_ADVERTISE.value,
                    self.server_id,
                    peer_sid,
                    payload,
                    sig=""
                )
                await self.send_envelope(ws, env)
            logger.debug("[%s] Sent presence catch-up to peer %s (count=%d)", self.server_id, peer_sid, len(self.local_users))
        except Exception as e:
            logger.error("[%s] Failed sending presence catch-up to %s: %s", self.server_id, peer_sid, e, exc_info=True)

    #Per-connection receive loop, parse and dispatch every incoming message on that socket
    async def handle_connection(self, ws):
        peer = ws.remote_address
        logger.info("[%s] New connection established from %s", self.server_id, peer)
        try:
            async for msg in ws:
                logger.debug("[%s] RAW message received: %s", self.server_id, msg)
                try:
                    envelope = Envelope.from_json(msg)
                    #if envelope.sender is a known server, update the self.server_last_seen
                    if envelope.sender in self.servers:
                        self.server_last_seen[envelope.sender] = int(time.time() * 1000)
                    #handle_connection receives the envelope
                    #then pass control to ServerProtocolHandler.handle_envelope() which containss the real logic for routing, broadcasting and erroring
                    logger.debug("Envelope received(handle_connection): type=%s sender=%s receiver=%s payload=%s",
                                envelope.type, envelope.sender, envelope.receiver, envelope.payload)

                    await self.server_proto_handler.handle_envelope(envelope, ws)
                except Exception as e:
                    logger.error("[%s] Error handling envelope: %s", self.server_id, e, exc_info=True)

        except websockets.exceptions.ConnectionClosed:
            logger.warning("[%s] Connection closed from %s", self.server_id, peer)
            # Cleanup any local user(s) bound to this websocket and broadcast removal
            try:
                to_remove = [uid for uid, _ws in list(self.local_users.items()) if _ws is ws]
                for uid in to_remove:
                    self.local_users.pop(uid, None)
                    if self.user_location.get(uid) == "local":
                        self.user_location.pop(uid, None)
                    # Optionally drop cached pubkey
                    self.user_pubkeys.pop(uid, None)
                    await self.broad_user_remove(uid)
            except Exception as e:
                logger.error("[%s] Disconnect cleanup failed: %s", self.server_id, e, exc_info=True)





    #send helper
    async def send_envelope(self, ws, envelope: Envelope):
        try:
            # Convert Envelope -> json
            if not getattr(envelope, "signature", None):
                self.sign_transport(envelope)

            message = envelope.to_json()
            await ws.send(message)
            logger.debug(
                "Sent envelope: type=%s sender=%s receiver=%s payload=%s",
                envelope.type, envelope.sender, envelope.receiver, envelope.payload
            )
        except Exception as e:
            logger.error("Failed to send envelope to %s: %s", envelope.receiver, str(e))    

    async def route_to_user(self, envelope: Envelope):
        target_user_id = envelope.receiver
        logger.debug("[%s] Routing message to user %s", self.server_id, target_user_id)

        if target_user_id in self.local_users:
            # Local delivery
            await self.send_user_deliver(envelope)

        elif target_user_id in self.user_location:
            # User is known to be on another server
            dest_server_id = self.user_location[target_user_id]
            if dest_server_id in self.servers:
                await self.send_server_deliver(envelope, dest_server_id)
            else:
                # Try to connect on-demand if we know the address
                addr = self.server_addrs.get(dest_server_id)
                if addr:
                    ok = await self.ensure_peer_connection(dest_server_id, addr[0], int(addr[1]))
                    if ok:
                        await self.send_server_deliver(envelope, dest_server_id)
                        return
                logger.error("[%s] user=%s mapped to server=%s but no route available",
                             self.server_id, target_user_id, dest_server_id)
                await self.send_error(envelope.sender, "USER_NOT_FOUND")

        else:
            # Unknown user entirely
            logger.warning("[%s] User %s not found locally or remotely, sender=%s",
                           self.server_id, target_user_id, envelope.sender)
            await self.send_error(envelope.sender, "USER_NOT_FOUND")



    async def send_login_response(self, ws, status: str, error: str = "", payload: dict = None):
        """
        Construct and send a LOGIN_RESPONSE envelope directly.
        """
        p = dict(payload or {})
        # normalize status + error fields for the client
        if status == "success":
            p.setdefault("status", "success")
        else:
            p["status"] = "fail"
            p["error"] = error

        env = Envelope(
            EnvelopeType.LOGIN_RESPONSE.value,
            sender=self.server_id,
            receiver="*",          # we’re writing back to the same websocket
            payload=p,
            sig=""
        )
        
        # optional: timestamp for tracing
        try:
            env.ts = int(time.time() * 1000)
        except Exception:
            pass

        await self.send_envelope(ws, env)

    async def send_register_response(self, ws, status: str, error: str = "", payload: dict = None):
        """
        Construct and send a REGISTER_RESPONSE envelope directly.
        """
        p = dict(payload or {})
        if status == "success":
            p.setdefault("status", "success")
        else:
            p["status"] = "fail"
            p["error"] = error

        env = Envelope(
            EnvelopeType.REGISTER_RESPONSE.value,
            sender=self.server_id,
            receiver="*",
            payload=p,
            sig=""
        )
        try:
            env.ts = int(time.time() * 1000)
        except Exception:
            pass

        await self.send_envelope(ws, env)


    #decide how to deliver a file transfer
    async def route_to_user_file_transfer(self, envelope: Envelope):
        target_user_id = envelope.receiver

        if target_user_id in self.local_users:
            await self.send_file_transfer(envelope)
        elif target_user_id in self.user_location:
            # Remote delivery: forward FILE_* envelope to the destination server
            dest_server_id = self.user_location[target_user_id]
            # ensure we have a socket to the destination server
            ws = self.servers.get(dest_server_id)
            if not ws:
                addr = self.server_addrs.get(dest_server_id)
                if addr:
                    ok = await self.ensure_peer_connection(dest_server_id, addr[0], int(addr[1]))
                    if ok:
                        ws = self.servers.get(dest_server_id)
            if ws:
                # make a safe copy of the payload and preserve original sender id
                fwd_payload = dict(envelope.payload)
                if "sender" not in fwd_payload:
                    fwd_payload["sender"] = envelope.sender

                fwd_env = Envelope(
                    envelope.type,            # FILE_START/FILE_CHUNK/FILE_END
                    self.server_id,            # transport-level sender = this server
                    target_user_id,            # receiver = actual user id at peer
                    fwd_payload,
                    sig=""
                )
                fwd_env.ts = envelope.ts
                await self.send_envelope(ws, fwd_env)
            else:
                await self.send_error(envelope.sender, "USER_NOT_FOUND")
        else:
            await self.send_error(envelope.sender, "USER_NOT_FOUND")

    # Envelope senders
    #Actually forward a direct message to a local recipient user
    # Deliver a direct message to a local recipient user
    async def send_user_deliver(self, msg_direct_envelope: Envelope):
        # make a safe copy (so we don't mutate original when reusing payload)
        payload = msg_direct_envelope.payload.copy()
        
        # validate envelope
        # validate_envelope(msg_direct_envelope)
        
        # ensure the payload retains the *original user sender ID* 
        # (because msg_direct_envelope.sender might have been a server in relay)
        if "sender" in payload:
            sender_id = payload["sender"]
        else:
            sender_id = msg_direct_envelope.sender
            payload["sender"] = sender_id  # tag the true origin
        
        payload["sender"] = sender_id
        
        sig = ""

        user_deliver_envelope = Envelope(
            EnvelopeType.USER_DELIVER.value,
            self.server_id,                       # transport-level sender = this server
            msg_direct_envelope.receiver,         # intended user
            payload,
            sig
        )

        user_deliver_envelope.ts = msg_direct_envelope.ts
        ws = self.local_users[msg_direct_envelope.receiver]

        logger.debug("[%s] Delivering direct message from %s to local user=%s",
                    self.server_id, sender_id, msg_direct_envelope.receiver)
        await self.send_envelope(ws, user_deliver_envelope)

    async def send_file_transfer(self, incoming_file: Envelope):
        payload = dict(incoming_file.payload)
        # tell the recipient who sent it preserve if already set by upstream server
        if "sender" not in payload:
            payload["sender"] = incoming_file.sender
        sig = "" # <- server1 signature over payload, placeholder until signed using send_envelope 
        file_transfer_envelope = Envelope(incoming_file.type, self.server_id, incoming_file.receiver, payload, sig)
        # Maintain original chunk timestamp information if the sender set it
        file_transfer_envelope.ts = incoming_file.ts

        ws = self.local_users[incoming_file.receiver]
        await self.send_envelope(ws, file_transfer_envelope)

    # Forward a user message to a peer server for final delivery
    async def send_server_deliver(self, msg_envelope: Envelope, dest_server_id: str):
        # safe copy
        payload = msg_envelope.payload.copy()
        
        # propagate the true user sender (not server)
        if "sender" in payload:
            sender_id = payload["sender"]
        else:
            sender_id = msg_envelope.sender
            payload["sender"] = sender_id
        
        payload["sender"] = sender_id
        payload["user_id"] = msg_envelope.receiver   # target user

        sig = "" 
        envelope = Envelope(
            EnvelopeType.SERVER_DELIVER.value,
            self.server_id,        # transport-level sender = this server
            dest_server_id,        # destination server
            payload,
            sig
        )
        envelope.ts = msg_envelope.ts  
        ws = self.servers[dest_server_id]

        logger.debug("[%s] Forwarding user message from %s to server=%s for user=%s",
                    self.server_id, sender_id, dest_server_id, msg_envelope.receiver)
        await self.send_envelope(ws, envelope)

    async def send_error(self, receiver: str, code: str, detail: str = ""):
        payload = {"code": code, "detail": detail}
        sig = ""
        envelope = Envelope(EnvelopeType.ERROR.value, self.server_id, receiver, payload, sig)

        logger.error("[%s] Sending error to receiver=%s: code=%s detail=%s",
                     self.server_id, receiver, code, detail)

        if receiver in self.local_users:
            await self.send_envelope(self.local_users[receiver], envelope)


    # Presence gossip
    #announce the user came online to all local users and all peer servers
    async def broadcast_user_advertise(self, user_id: str, meta: dict):
        payload = {"user_id": user_id, "server_id": self.server_id, "meta": meta}
        sig = ""
        envelope = Envelope(EnvelopeType.USER_ADVERTISE.value, self.server_id, "*", payload, sig)

        logger.debug("[%s] Broadcasting USER_ADVERTISE for user=%s", self.server_id, user_id)

        # Send to every local user, except the advertising user 
        for uid, ws in self.local_users.items():
            if uid == user_id:
                continue  # skip sending back to the same user
            logger.debug("[%s] -> Sending USER_ADVERTISE about %s to LOCAL user=%s",
                        self.server_id, user_id, uid)
            await self.send_envelope(ws, envelope)

        # Send to every peer server 
        for sid, ws in self.servers.items():
            logger.debug("[%s] -> Sending USER_ADVERTISE about %s to SERVER=%s",
                        self.server_id, user_id, sid)
            await self.send_envelope(ws, envelope)

    # async def send_existing_users_to(self, new_user, ws):
    #     for uid, existing_user in self.online_users.items():
    #         if uid == new_user.user_id:
    #             continue
    #         advert = Envelope(
    #             type=EnvelopeType.USER_ADVERTISE.value,
    #             payload={
    #                 "user_id": uid,
    #                 "server_id": self.server_id,
    #                 "meta": {"pubkey": existing_user.public_key_b64},
    #             },
    #             sender=self.server_id,
    #             receiver=new_user.user_id,
    #         )
    #         await ws.send(advert.to_json())
    

    # broadcast the user went offline to all local clients and peer servers
    async def broad_user_remove(self, user_id: str):
        payload = {"user_id": user_id, "server_id": self.server_id}
        sig = ""
        envelope = Envelope(EnvelopeType.USER_REMOVE.value, self.server_id, "*", payload, sig)

        logger.debug("[%s] Broadcasting USER_REMOVE for user=%s", self.server_id, user_id)

        # Send to every local user
        for uid, ws in self.local_users.items():
            logger.debug("[%s] -> Sending USER_REMOVE for %s to LOCAL user=%s",
                         self.server_id, user_id, uid)
            await self.send_envelope(ws, envelope)

        # Send to every peer server
        for sid, ws in self.servers.items():
            logger.debug("[%s] -> Sending USER_REMOVE for %s to SERVER=%s",
                         self.server_id, user_id, sid)
            await self.send_envelope(ws, envelope)



    async def send_server_hello_join(self, introducer_host, introducer_port, introducer_id="*"):
        uri = f"ws://{introducer_host}:{introducer_port}"
        logger.debug("[%s] Attempting SERVER_HELLO_JOIN with introducer at %s", self.server_id, uri)

        try:
            # Persistent connection to introducer
            ws = await websockets.connect(uri)

            # Build join request
            ts = int(time.time() * 1000)
            payload = {
                "host": self.host,
                "port": self.port,
                "pubkey": self.server_pub_b64,
            }
            env = Envelope(
                EnvelopeType.SERVER_HELLO_JOIN.value,
                sender=self.server_id,   # temp id
                receiver=introducer_id,
                payload=payload,
                sig=""
            )
            env.ts = ts

            await self.send_envelope(ws, env)

            # Store introducer connection in servers map
            # After storing ws in self.servers
            self.servers["introducer"] = ws
            self.server_addrs["introducer"] = (introducer_host, introducer_port)

            asyncio.create_task(self.listen_to_peer(ws))

            return True

        except Exception as e:
            logger.error("[%s] Failed SERVER_HELLO_JOIN with %s: %s",
                        self.server_id, uri, e, exc_info=True)
            return False

    async def send_server_welcome(self, assigned_id: str,temp_id: str,ws):
        peers = []
        for sid, (h, p) in self.server_addrs.items():
            if sid != assigned_id:
                peers.append({"user_id": sid, "host": h, "port": p, "pubkey": self.server_pubkeys.get(sid, "")})

        payload = {
            "assigned_id": assigned_id,
            "clients": peers
        }

        welcome = Envelope(
            EnvelopeType.SERVER_WELCOME.value,
            self.server_id,
            temp_id,
            payload,
            sig="" 
        )

        await self.send_envelope(ws, welcome)
        logger.debug("[%s][Introducer] Assigned %s to newcomer %s with peers=%s",
                    self.server_id, assigned_id, temp_id, peers)

    async def send_server_announce(self):
        ts = int(time.time() * 1000)
        payload = {
            "host": self.host,
            "port": self.port,
            "pubkey": self.server_pub_b64
        }

        announce_env = Envelope(
            EnvelopeType.SERVER_ANNOUNCE.value,
            self.server_id,   # from: our server_id
            "*",              # broadcast
            payload,
            sig=""           
        )
        announce_env.ts = ts

        # Send to all connected peers
        for ws in self.servers.values():
            await self.send_envelope(ws, announce_env)
        
        logger.debug("[%s] Broadcasted SERVER_ANNOUNCE to peers", self.server_id)



    #health 
    #periodically ping peer servers to check they are alive, and warns if a server looks stale
    async def heartbeat_loop(self):
        #loop runs only when the server is marked "running"
        while self.running:
            #current time
            time_now = int(time.time() * 1000)
            #iterate over connected peer servers, list guard against dict size changing mid-iteration
            #send this hearbeat specifically to server sid
            for sid, ws in list(self.servers.items()):
                payload = {} # Need to be implemented
                #self.sever_id is the sender of the envelope, the receiver will know which server sent this heartbeat

                env = Envelope(EnvelopeType.HEARTBEAT.value, self.server_id, sid, payload, "")

                try:
                    #send the env and other server should receive a JSON heartbeat
                    await self.send_envelope(ws, env)
                    #Look in the dictionary self.server_last seen for the last time we heard from this peer server sid
                    #returns the timestamp in ms when we last saw a message from that server or 0 we haven't record anything yet
                    last_seen = self.server_last_seen.get(sid, 0)
                    #check if we have the record time, and check how many milliseconds ago did we last hear from this peer
                    if last_seen and (time_now - last_seen) > HEARTBEAT_TIMEOUT * 1000:
                        #send a warning
                        logger.warning("[%s] WARN: %s last seen %sms ago",
                                       self.server_id, sid, time_now - last_seen)
                except Exception as e:
                    logger.error("[%s] HEARTBEAT send failed to %s: %s",
                                 self.server_id, sid, str(e), exc_info=True) #after looping through all peers and sending them heartbeats, the function pauses for sometimes
            await asyncio.sleep(HEARTBEAT_INTERVAL)

    
    async def listen_to_peer(self, ws):
        try:
            async for msg in ws:
                envelope = Envelope.from_json(msg)
                logger.debug("Envelope received(from introducer): %s", envelope.type)
                await self.server_proto_handler.handle_envelope(envelope, ws)
        except websockets.exceptions.ConnectionClosed:
            logger.warning("[%s] Connection to peer/introducer closed", self.server_id)
