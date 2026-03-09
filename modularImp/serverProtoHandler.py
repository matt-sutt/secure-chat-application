import websockets
import logging
from .EnvelopeType import EnvelopeType
from .envelope import Envelope
import time
import base64
import json
from socp.modularImp.logging_config import setup_logging, module_logger

# logging
setup_logging()
SILENCE = 0
logger = module_logger(__name__, silence=bool(SILENCE))

# silence logs
logging.getLogger("asyncio").disabled = True
logging.getLogger("websockets").disabled = True
logging.getLogger("websockets.client").disabled = True
logging.getLogger("websockets.server").disabled = True
logging.getLogger("Database").disabled = True

class ServerProtocolHandler:
    def __init__(self, server):
        self.server = server
        logger.info("ServerProtocolHandler initialized for server_id=%s", self.server.server_id)

    #Read the envelop's type and branches
    async def handle_envelope(self, envelope: Envelope, ws):
        logger.debug(
            "Received envelope: type=%s sender=%s receiver=%s payload=%s",
            envelope.type, envelope.sender, envelope.receiver, envelope.payload
        )
        #for each known type, calls a specific handle method
        etype = envelope.type

        # Drop duplicate server-delivered frames to prevent loops
        try:
            if self.server.is_peer_socket(ws):
                if self.server.seen_s2s_duplicate(envelope):
                    logger.debug("[DEDUP] Dropping duplicate frame type=%s from=%s to=%s ts=%s",
                                 etype, envelope.sender, envelope.receiver, getattr(envelope, 'ts', None))
                    return
        except Exception:
            # Non-fatal if dedup check fails
            pass

        if etype == EnvelopeType.USER_HELLO.value:
            return await self.handle_user_hello(envelope, ws)

        elif etype == EnvelopeType.MSG_DIRECT.value:
            return await self.handle_msg_direct(envelope)

        elif etype == EnvelopeType.MSG_PUBLIC_CHANNEL.value:
            return await self.handle_public_channel_message(envelope)

        elif etype in {
            EnvelopeType.FILE_START.value,
            EnvelopeType.FILE_CHUNK.value,
            EnvelopeType.FILE_END.value
        }:
            return await self.handle_file(envelope)

        elif etype == EnvelopeType.SERVER_HELLO_JOIN.value:
            return await self.handle_server_hello_join(envelope, ws)

        elif etype == EnvelopeType.SERVER_WELCOME.value:
            return await self.handle_server_welcome(envelope,ws)

        elif etype == EnvelopeType.SERVER_ANNOUNCE.value:
            return await self.handle_server_announce(envelope, ws)

        elif etype == EnvelopeType.USER_ADVERTISE.value:
            return await self.handle_user_advertise(envelope)

        elif etype == EnvelopeType.USER_REMOVE.value:
            return await self.handle_user_remove(envelope)

        elif etype == EnvelopeType.SERVER_DELIVER.value:
            return await self.handle_server_deliver(envelope)

        elif etype == EnvelopeType.HEARTBEAT.value:
            return await self.handle_heartbeat(envelope)
        
        elif etype == EnvelopeType.ERROR.value:
            return await self.handle_error(envelope)

        elif etype == EnvelopeType.ACK.value:
            return await self.handle_ack(envelope)
        

        elif etype == EnvelopeType.REGISTER.value:
            return await self.handle_register(envelope, ws)
        
        elif etype == EnvelopeType.LOGIN.value:
            return await self.handle_login(envelope,ws)
        
        else:
            logger.warning("[%s] Unknown envelope type received: %s", self.server.server_id, etype)
            await self.server.send_error(envelope.sender, "UNKNOWN_TYPE")
    
    #database user login
    async def handle_login(self, envelope, ws):
        username = envelope.payload.get("username")
        password = envelope.payload.get("password")

        logger.info("[LOGIN] Login request for username=%s password=%s", username, password)

        auth = self.server.db.authenticate_user(username, password)
        if not auth or not auth.get("Login_Status"):
            err = auth.get("error") if isinstance(auth, dict) else "invalid-credentials"
            logger.warning("[LOGIN] Login fail username=%s error=%s", username, err)
            await self.server.send_login_response(ws, status="fail", error=err)
            return

        full = self.server.db.get_user_full_by_username(username)
        if not full:
            await self.server.send_login_response(ws, status="fail", error="profile-not-found-after-login")
            return

        full_json = {
            "user_id": full["user_id"],
            "username": full["username"],
            "pubkey_b64": full["pubkey_b64"],
            "privkey_store_b64": base64.b64encode(full["privkey_store_b64"]).decode("ascii"),
            "created_at": full["created_at"]
        }

        logger.info("[LOGIN] successful login for user=%s uid=%s priv_blob_len=%s",
                    username, full_json["user_id"], len(full["privkey_store_b64"]))

        payload = {
            "status": "success",
            "user": full_json,
            "server": {
                "server_id": self.server.server_id,
                "host": self.server.host,
                "port": self.server.port,
                "pubkey": self.server.server_pub_b64,
                "known_users": {},
                "known_pubkeys": {}
            }
        }

        #add in known users and pubkeys


        # add to know user with format
        await self.server.send_login_response(ws, status="success", payload=payload)

    #database user register
    async def handle_register(self, envelope, ws):
        username = envelope.payload.get("username")
        password = envelope.payload.get("password")

        logger.info("[REGISTER] Registration request for username=%s password=%s", username, password)

        result = self.server.db.register_user(username, password)
        if not result or not result.get("Register_Status"):
            err = result.get("error") if isinstance(result, dict) else "register failed"
            logger.warning("[REGISTER] failed username=%s error=%s", username, err)
            await self.server.send_register_response(ws, status="fail", error=err)
            return

        full = self.server.db.get_user_full_by_username(username)
        if not full:
            await self.server.send_register_response(ws, status="fail", error="profile-not-found-after-register")
            return

        full_json = {
            "user_id": full["user_id"],
            "username": full["username"],
            "pubkey_b64": full["pubkey_b64"],
            "privkey_store_b64": base64.b64encode(full["privkey_store_b64"]).decode("ascii"),
            "created_at": full["created_at"],
        }

        logger.info("[REGISTER] successful registration for user=%s uid=%s priv_blob_len=%s",
                    username, full_json["user_id"], len(full["privkey_store_b64"]))

        payload = {
            "status": "success",
            "user": full_json,
            "server": {
                "server_id": self.server.server_id,
                "host": self.server.host,
                "port": self.server.port,
                "pubkey": self.server.server_pub_b64
            }
        }
        await self.server.send_register_response(ws, status="success", payload=payload)



    #A client sends its initial hello (after Websocket connect)
    async def handle_user_hello(self, envelope: Envelope, ws):
        user_id = envelope.sender
        logger.debug("USER_HELLO received from user_id=%s", user_id)

        if user_id in self.server.local_users:
            # Reject the new connection attempting to reuse an online user_id.
            try:
                payload = {"code": "NAME_IN_USE", "detail": ""}
                err_env = Envelope(
                    EnvelopeType.ERROR.value,
                    self.server.server_id,
                    "*",
                    payload,
                    sig=""
                )
                await self.server.send_envelope(ws, err_env)
            except Exception:
                pass
            # close the duplicate session, keep the existing user connected
            try:
                await ws.close()
            except Exception:
                pass
            return
        #register the client's socket
        self.server.local_users[user_id] = ws
        self.server.user_location[user_id] = "local"

        client_pub = envelope.payload.get("pubkey_b64")
        if client_pub:
            # Validate RSA-4096 client pubkey before accepting
            try:
                key_obj = self.server.crypto.load_public_key_b64url(client_pub)
                # If load/validation succeeds, cache b64 string
                self.server.user_pubkeys[user_id] = client_pub
            except Exception:
                # Reject bad key
                payload = {"code": "BAD_KEY", "detail": "RSA-4096 required"}
                err_env = Envelope(EnvelopeType.ERROR.value, self.server.server_id, "*", payload, sig="")
                await self.server.send_envelope(ws, err_env)
                try:
                    await ws.close()
                except Exception:
                    pass
                return
    
        logger.info(f"Local users: {list(self.server.local_users.keys())}")
        #All local users and peer servers learn that user_id is online
        meta = {
            "pubkey_b64": self.server.user_pubkeys.get(user_id)
        }

        #  send catch-up USER_ADVERTISE to this newly logged-in user
        # Tell them about everyone else already online on this server
        for other_uid, _other_ws in self.server.local_users.items():
            if other_uid == user_id:
                continue
            other_pub = self.server.user_pubkeys.get(other_uid)
            if not other_pub:
                continue
            payload = {
                "user_id": other_uid,
                "server_id": self.server.server_id,
                "meta": {"pubkey_b64": other_pub},
            }
            # receiver = this user
            advert = Envelope(
                EnvelopeType.USER_ADVERTISE.value,
                self.server.server_id,
                user_id,
                payload,
                sig=""  # transport signer will add signature in send_envelope
            )
            await self.server.send_envelope(ws, advert)
            logger.info("Catch-up advertise: told %s about already-online %s",
                        user_id, other_uid)

        await self.server.broadcast_user_advertise(user_id, meta)

        # Also send catch-up USER_ADVERTISE entries for any remote users we already know about
        try:
            for uid, sid in list(self.server.user_location.items()):
                if uid == user_id:
                    continue
                if sid == "local":
                    continue
                pub = self.server.user_pubkeys.get(uid)
                if not pub:
                    continue
                payload = {
                    "user_id": uid,
                    "server_id": sid,
                    "meta": {"pubkey_b64": pub},
                }
                advert = Envelope(
                    EnvelopeType.USER_ADVERTISE.value,
                    self.server.server_id,
                    user_id,
                    payload,
                    sig=""
                )
                await self.server.send_envelope(ws, advert)
                logger.info("Catch-up advertise(remote): told %s about remote %s @ %s",
                            user_id, uid, sid)
        except Exception as e:
            logger.warning("Remote presence catch-up to %s failed: %s", user_id, e)


    #when a client sends a direct message (MSG_DIRECT) to a specific user
    async def handle_msg_direct(self, envelope: Envelope):
        #Delegates tot the server's router
        await self.server.route_to_user(envelope)

    #public channel messaging, broadcasting 
    async def handle_public_channel_message(self, envelope: Envelope):
        payload = envelope.payload or {}
        sender_user = envelope.sender
        ts_ms = envelope.ts

        # Validate required fields exist in payload
        for k in ("ciphertext", "sender_pub", "content_sig"):
            if k not in payload:
                logger.warning("[PUBLIC] Missing '%s' in payload, dropping.", k)
                return

        delivered_local = 0
        for uid, ws in list(self.server.local_users.items()):
            if uid == sender_user:
                continue  # don't echo back to sender
            try:
                # Keep original sender set receiver to the specific user
                out_env = Envelope(
                    EnvelopeType.MSG_PUBLIC_CHANNEL.value,
                    sender_user,
                    uid,
                    payload,
                    sig=""
                )
                out_env.ts = ts_ms
                await self.server.send_envelope(ws, out_env)
                delivered_local += 1
            except Exception as e:
                logger.error("[PUBLIC] Deliver to local user %s failed: %s", uid, e, exc_info=True)

        logger.info("[PUBLIC] Fan-out local deliveries=%d", delivered_local)
        # Forward to peer servers only when originating from a local client
        # Local client messages have receiver == "public". Peer-forwarded ones have receiver set to a server id.
        if getattr(envelope, "receiver", None) == "public" and self.server.servers:
            forwarded = 0
            for sid, pws in list(self.server.servers.items()):
                try:
                    out_env = Envelope(
                        EnvelopeType.MSG_PUBLIC_CHANNEL.value,
                        sender_user,
                        sid,   # deliver to peer server transport endpoint
                        payload,
                        sig=""
                    )
                    out_env.ts = ts_ms
                    await self.server.send_envelope(pws, out_env)
                    forwarded += 1
                except Exception as e:
                    logger.error("[PUBLIC] Forward to peer %s failed: %s", sid, e, exc_info=True)
            logger.info("[PUBLIC] Forwarded to %d peer servers", forwarded)

    async def handle_file(self, envelope: Envelope):
        await self.server.route_to_user_file_transfer(envelope)


    #peer server join
    async def handle_server_hello_join(self, envelope: Envelope, ws):
        new_host = envelope.payload.get("host")
        new_port = envelope.payload.get("port")
        new_pubkey = envelope.payload.get("pubkey")

        temp_id = envelope.sender

        logger.debug("Received SERVER_HELLO_JOIN from %s at %s:%s", temp_id, new_host, new_port)

        assigned_id = f"server_{len(self.server.server_addrs) + 1}"

        self.server.servers[assigned_id] = ws
        self.server.server_addrs[assigned_id] = (new_host, new_port)
        self.server.server_last_seen[assigned_id] = envelope.ts
        self.server.server_pubkeys[assigned_id] = new_pubkey

        logger.debug("[%s][handle_server_hello_join] Assigned new server_id=%s for peer=%s", self.server.server_id, assigned_id, temp_id)

        await self.server.send_server_welcome(assigned_id, temp_id,ws)

    async def handle_server_welcome(self, envelope: Envelope, ws):
        assigned_id   = envelope.payload["assigned_id"]     # our final id
        introducer_id = envelope.sender                      # real id of the peer we joined

        self.server.server_id = assigned_id
        logger.debug("Received SERVER_WELCOME, assigned id=%s", assigned_id)

        # Rebind placeholder "introducer" -> real introducer_id
        servers = self.server.servers
        addrs   = self.server.server_addrs

        if "introducer" in servers:
            existing_ws = servers.pop("introducer")
            # prefer the actual existing socket, fall back to current ws just in case
            servers[introducer_id] = existing_ws or ws
        else:
            # ensure we have a mapping for the introducer we just spoke to
            servers.setdefault(introducer_id, ws)

        if "introducer" in addrs:
            addrs[introducer_id] = addrs.pop("introducer")

        # Prime heartbeat freshness based on this welcome’s timestamp
        self.server.server_last_seen[introducer_id] = envelope.ts

        # Register any peers the introducer told us about
        for peer in envelope.payload.get("clients", []):
            pid, phost, pport = peer["user_id"], peer["host"], peer["port"]
            addrs[pid] = (phost, pport)
            logger.debug("Registered peer server=%s at %s:%s", pid, phost, pport)
            if hasattr(self.server, "server_pubkeys") and "pubkey" in peer:
                try:
                    self.server.crypto.load_public_key_b64url(peer["pubkey"])  # validates 4096
                    self.server.server_pubkeys[pid] = peer["pubkey"]
                except Exception:
                    logger.warning("Ignored non-4096 pubkey for peer server=%s", pid)
            # Proactively connect to peer if not already connected
            try:
                await self.server.ensure_peer_connection(pid, phost, int(pport))
            except Exception as e:
                logger.warning("Failed to connect to peer %s at %s:%s: %s", pid, phost, pport, e)

        # Now that our id is finalized, announce ourselves
        await self.server.send_server_announce()
        logger.debug("Broadcasted SERVER_ANNOUNCE after join")

    async def handle_server_announce(self, envelope: Envelope, ws):
        sid    = envelope.sender
        host   = envelope.payload.get("host")
        port   = envelope.payload.get("port")
        pubkey = envelope.payload.get("pubkey")

        # Update address book
        self.server.server_addrs[sid] = (host, port)

        # Count announce as activity for heartbeat freshness
        self.server.server_last_seen[sid] = envelope.ts

        if hasattr(self.server, "server_pubkeys") and pubkey:
            try:
                self.server.crypto.load_public_key_b64url(pubkey)  # validates 4096
                self.server.server_pubkeys[sid] = pubkey
            except Exception:
                logger.warning("Ignored non-4096 pubkey in SERVER_ANNOUNCE from %s", sid)

        logger.debug("[%s] SERVER_ANNOUNCE received from sid=%s at %s:%s",
                    self.server.server_id, sid, host, port)
        # Bind inbound websocket to this peer if not already tracked and send presence catch-up
        try:
            bound_new = False
            if sid != self.server.server_id and sid not in self.server.servers and ws is not None:
                self.server.servers[sid] = ws
                bound_new = True
                logger.debug("Bound inbound websocket to peer sid=%s", sid)
            if bound_new:
                await self.server.send_presence_catchup_to_peer(sid)
        except Exception as e:
            logger.warning("Binding/Presence catch-up to %s failed: %s", sid, e)
        # Ensure we have an outbound route if needed
        if sid != self.server.server_id and sid not in self.server.servers:
            try:
                await self.server.ensure_peer_connection(sid, host, int(port))
            except Exception as e:
                logger.warning("ensure_peer_connection failed for %s at %s:%s: %s", sid, host, port, e)


    #When presence broadcast arrives saying "user X is online at server S"
    async def handle_user_advertise(self, envelope: Envelope):
        #record/updates where that user lives
        uid = envelope.payload["user_id"]
        sid = envelope.payload["server_id"]
        self.server.user_location[uid] = sid

        logger.info("Presence update: user=%s is now online at server=%s", uid, sid)

        # Cache remote user's pubkey if present in meta for later catch-up to new clients
        try:
            meta = envelope.payload.get("meta", {}) or {}
            pub = meta.get("pubkey_b64")
            if pub:
                self.server.user_pubkeys[uid] = pub
        except Exception:
            pass

        # Rewrap and forward to all local clients so transport signature verifies
        try:
            for local_uid, lws in list(self.server.local_users.items()):
                advert = Envelope(
                    EnvelopeType.USER_ADVERTISE.value,
                    self.server.server_id,
                    local_uid,
                    envelope.payload,
                    sig=""
                )
                await self.server.send_envelope(lws, advert)
        except Exception as e:
            logger.error("Forwarding USER_ADVERTISE to local clients failed: %s", e, exc_info=True)



    #When a Presense broadcast arrives saying "user X went offline at server S"
    async def handle_user_remove(self, envelope: Envelope):
        uid = envelope.payload["user_id"]
        sid = envelope.payload["server_id"]
        #if the map says that user is at the same server, remove the entry
        #make sure only delete the user if info matches the server they are being removed from

        if self.server.user_location.get(uid) == sid:
            del self.server.user_location[uid]
            logger.info("User %s removed from server %s", uid, sid)
        else:
            logger.debug("USER_REMOVE ignored for %s (mismatched server_id)", uid)

        # Rewrap and forward removal to all local clients
        try:
            for local_uid, lws in list(self.server.local_users.items()):
                removal = Envelope(
                    EnvelopeType.USER_REMOVE.value,
                    self.server.server_id,
                    local_uid,
                    envelope.payload,
                    sig=""
                )
                await self.server.send_envelope(lws, removal)
        except Exception as e:
            logger.error("Forwarding USER_REMOVE to local clients failed: %s", e, exc_info=True)


    #another server forwarded you a message meant for one of the local users
    async def handle_server_deliver(self, envelope: Envelope):

        # Extract user id from payload if present
        user_id = None
        if isinstance(envelope.payload, dict):
            user_id = envelope.payload.get("user_id")

        logger.debug("Delivering message from %s to local recipient (raw receiver=%s payload_user=%s)",
                    envelope.sender, envelope.receiver, user_id)

        if not user_id:
            # malformed forward, log and notify sender
            logger.warning("[%s] SERVER_DELIVER missing payload.user_id, sender=%s",
                            self.server.server_id, envelope.sender)
            await self.server.send_error(envelope.sender, "USER_NOT_FOUND", "missing user_id in payload")
            return

        # replace envelope.receiver with actual target user id and route
        envelope.receiver = user_id
        await self.server.route_to_user(envelope)    

    #another server oings you with a heartbeat
    async def handle_heartbeat(self, envelope: Envelope):
        #incase there too many heartbeats
        if envelope.sender and envelope.sender != self.server.server_id:
            self.server.server_last_seen[envelope.sender] = int(time.time() * 1000)
        logger.debug("[HB] heartbeat received from %s", envelope.sender)

    def handle_error(self, envelope: Envelope):
        logger.error("[%s] Error from %s: %s", self.server.server_id, envelope.sender, envelope.payload)


    #someone acknoledge the message sent
    async def handle_ack(self, envelope: Envelope):
        logger.info("[%s] ACK received from %s: %s", self.server.server_id, envelope.sender, envelope.payload)
