import logging #logging for diagnostics and observability
# import asyncio
import time #timestamps for file transfer metrics
from .envelope import Envelope #
import os
from .EnvelopeType import EnvelopeType #enumerate all envelope types used by the protocol
 #initialize the logging handlers
from socp.modularImp.logging_config import setup_logging
setup_logging()
import json
import os
from pathlib import Path

logger = logging.getLogger("Server")

from socp.modularImp.logging_config import setup_logging, module_logger
setup_logging()
SILENCE = 0
logger = module_logger(__name__, silence=bool(SILENCE))

logging.disable(logging.NOTSET)
logging.getLogger("asyncio").disabled = True # silence asyncio logs
logging.getLogger("websockets").disabled = True # silence websockets logs
logging.getLogger("websockets.client").disabled = True # silence client logs
logging.getLogger("websockets.server").disabled = True # silence server logs
logging.getLogger("Database").disabled = True # silence database logs

class UserProtoHandler:
    def __init__(self, user):
        self.user = user  
        #Try to log the user info
        logger.debug("UserProtoHandler initialized for user_id=%s", self.user.user_id)

    #This is called whenever there is a message sent from server to user
    async def handle_envelope(self, envelope: Envelope):
        logger.debug("User %s handling envelope type=%s", self.user.user_id, envelope.type)
        #Get the type of the message
        envelope_type = envelope.type
 
        #Dispatcher: routes every message type to the right specialized handler
        if envelope_type == EnvelopeType.USER_DELIVER.value:
            await self.handle_user_deliver(envelope)
        elif envelope_type == EnvelopeType.ERROR.value:
            await self.handle_error(envelope)
        elif envelope_type == EnvelopeType.ACK.value:
            #acknoledge for earlier client requests
            await self.handle_ack(envelope)
        elif envelope_type == EnvelopeType.MSG_PUBLIC_CHANNEL.value:
            #public channel broadcast
            await self.handle_public_channel_message(envelope)
        elif envelope_type == EnvelopeType.FILE_START.value:
            #begin incoming file transfer
            await self.handle_file_start(envelope)
        elif envelope_type == EnvelopeType.FILE_CHUNK.value:
            #Receive a piece of file
            await self.handle_file_chunk(envelope)
        elif envelope_type == EnvelopeType.FILE_END.value:
            #Finalize file reassembly and save to disk
            await self.handle_file_end(envelope)
        # elif envelope_type == EnvelopeType.PUBLIC_CHANNEL_KEY_SHARE.value:
        #     await self.handle_public_channel_key_share(envelope)
        elif envelope_type == EnvelopeType.USER_ADVERTISE.value:
            #show user online
            await self.handle_user_advertise(envelope)
        elif envelope_type == EnvelopeType.USER_REMOVE.value:
            #show user offline
            await self.handle_user_remove(envelope)
        else:
            logger.warning("User %s received unknown envelope type: %s", self.user.user_id, envelope_type)
    # direct person-to-person message
    async def handle_user_deliver(self, envelope: Envelope):
        payload = envelope.payload
        logger.debug("[DM] handle_user_deliver invoked for user_id=%s | payload_keys=%s",
                    self.user.user_id, list(payload.keys()))

        sender_pub_b64 = payload.get("sender_pub")
        if not sender_pub_b64: # if encrypted payload does not include sender_pub
            logger.warning("[DM] Missing sender_pub in payload for user=%s", self.user.user_id)
            return

        try: # try loading the sender_pub key for users
            sender_pub = self.user.cryp.load_public_key_b64url(sender_pub_b64)
            logger.debug("[DM] Loaded sender_pub key (len=%d bytes) for user=%s",
                        len(sender_pub_b64), self.user.user_id)
        except Exception as e:
            logger.exception("[DM] Failed to load sender_pub for %s: %s", self.user.user_id, e)
            return

        ts = envelope.ts

        ok = self.user.cryp.verify_dm_content_sig(
            sender_pub,
            payload["ciphertext"],
            payload.get("sender", envelope.sender),  # from
            self.user.user_id,
            ts,
            payload.get("content_sig"),
        )



        # also dump the payload specifically
        payload = envelope.payload
        if not ok:
            logger.warning("[DM] Invalid content_sig for recipient=%s from sender=%s",
                        self.user.user_id, envelope.sender)
            return

        sender = payload.get("sender", "Unknown")
        ciphertext_b64 = payload["ciphertext"]

        logger.debug("[DM] Signature verified; attempting RSA-OAEP decrypt (len=%d)",
                    len(ciphertext_b64))
        

        try:
            plaintext = self.user.cryp.decrypt_rsa_oaep_b64(
                self.user.private_key, ciphertext_b64
            ).decode("utf-8")
        except Exception as e:
            logger.exception("[DM] Decryption failed for user=%s from=%s: %s",
                            self.user.user_id, sender, e)
            return


        # Display for interactive CLI
        print(f"\n--- Direct Message from {sender} ---")
        print(f"{plaintext}")
        print("--- End Message ---\n")

        # Log it for debugging
        logger.debug("[DM] User %s received DIRECT message from %s: %s",
                    self.user.user_id, sender, plaintext)

        # Send delivery ACK back to server
        try:
            msg_ref = f"dm:{envelope.ts}"
            await self.user.send_ack(envelope, msg_ref)
        except Exception as e:
            logger.exception("[DM] Failed to send ACK for user=%s: %s", self.user.user_id, e)

        # only add the new user when it is not in the list
        if sender not in self.user.known_users:
            self.user.known_users[sender] = envelope.sender
            logger.debug("[DM] Added new sender=%s to known_users (now %d entries) for user=%s",
                        sender, len(self.user.known_users), self.user.user_id)

        # Extra visibility: summary of pubkey cache state
        logger.debug("[DM] known_users=%s | known_pubkeys=%s",
                    list(self.user.known_users.keys()),
                    list(getattr(self.user, 'known_pubkeys', {}).keys()))


    #For receiving the braodcast payloads
    async def handle_public_channel_message(self, envelope):
        """Verify + decrypt an incoming public-channel chat. Prints full debug and shows plaintext."""
        # print("\n=== INCOMING PUBLIC MESSAGE DEBUG ===")
        # try:
        #     print(json.dumps(envelope.__dict__, indent=2, default=str))
        # except Exception as e:
        #     print("Envelope dump failed:", e)

        payload = envelope.payload or {}
        from_id = envelope.sender if hasattr(envelope, "sender") else envelope.from_
        ts_ms   = envelope.ts

        # Basic presence checks
        for k in ["ciphertext", "sender_pub", "content_sig"]:
            if k not in payload:
                print(f"[WARN] Missing '{k}' in payload; dropping.")
                return

        ciphertext_b64 = payload["ciphertext"]
        sender_pub_b64 = payload["sender_pub"]
        sig_b64        = payload["content_sig"]
        
        # Load sender's pubkey + verify e2e signature 
        try:
            sender_pub = self.user.cryp.load_public_key_b64url(sender_pub_b64)
        except Exception as e:
            print("[ERROR] Could not load sender_pub:", e)
            return

        ok = self.user.cryp.verify_public_content_sig(
            sender_pub,
            ciphertext_b64,
            from_id,
            ts_ms,
            sig_b64
        )

        if not ok:
            print("[WARN] Invalid content_sig; dropping.")
            return

        # Decrypt with Public Channel private key (RSA-OAEP, SHA-256)
        try:
            plaintext = self.user.cryp.decrypt_rsa_oaep_b64(self.user.public_channel_priv, ciphertext_b64).decode("utf-8")
        except Exception as e:
            print("[ERROR] Public-channel decryption failed:", e)
            return

        # cli display
        print(f"\n--- Public @ {from_id} ---")
        print(plaintext)
        print("--- End Public Message ---\n")
        # print("=== END INCOMING DEBUG ===\n")

    async def handle_file_start(self, envelope: Envelope):
        p = envelope.payload
        #unique indentifier to correlate chunk
        file_id = p.get("file_id")
        #output filename to save when done
        name = p.get("name")
        #Total file size in bytes
        size = int(p.get("size", 0))
        #Total number of chunks we expect to receive
        total = int(p.get("total_chunks", 0))
        #sanity check
        #Must have a file_id, name and the number of chunks need to be positive
        if not file_id or not name or total <= 0:
            print("[FILE] Bad FILE_START payload")
            return

        #initialise a transfer record, to track progress while chunks arrive
        #Using dictionary to be more friendly to out-of-order and save space as we dont have to pre-allocate a huge space or array or list
        self.user.incoming_files[file_id] = {
            "name": name, 
            "size": size, 
            "total": total, 
            "received": 0, 
            "buf": {}, 
            "ts": time.time(),
            "sender": p.get("sender", envelope.sender), 
        }
        print(f"[FILE] START recv: {name} ({size} bytes, {total} chunks) from {p.get('sender', envelope.sender)}")

    async def handle_file_chunk(self, envelope: Envelope):
        p = envelope.payload
        file_id = p.get("file_id")
        index = p.get("index")
        ciphertext = p.get("ciphertext")
        #if the file come from no where, ignore it
        if file_id not in self.user.incoming_files:
            print("[FILE] CHUNK for unknown file_id")
            return

        # Decrypt RSA ciphertext (base64url) -> plaintext bytes
        try:
            clear = self.user.cryp.decrypt_rsa_oaep_b64(self.user.private_key, ciphertext)
        except Exception as e:
            print(f"[FILE] RSA decrypt failed on chunk {index}: {e}")
            return
        #fetch the transfer state dict
        info = self.user.incoming_files[file_id]

        # If this index already arrived, ignore the duplicates
        #safe for sender to retry and race conditions 
        if index in info["buf"]:
            return
        #Store the plaintext bytes for this chunk at its index
        info["buf"][index] = clear
        #increment the count of unique chunks received 
        info["received"] += 1
        #Progress feedback; check every 16 chunks or when we fully received it
        if info["received"] % 16 == 0 or info["received"] == info["total"]:
            print(f"[FILE] recv chunks {info['received']}/{info['total']} for {info['name']}")

    async def handle_file_end(self, envelope: Envelope):
        p = envelope.payload
        file_id = p.get("file_id")
        #same as previous, ditch the unknown file
        if file_id not in self.user.incoming_files:
            print("[FILE] END for unknown file_id")
            return

        info = self.user.incoming_files[file_id]
        name = info["name"]
        total = info["total"]

        # Protocol expectation: by FILE_END, the receiver should have all indices [0..total-1].
        # If any are missing, the transfer is incomplete then we ditch it.
        missing = [i for i in range(total) if i not in info["buf"]]
        if missing:
            print(f"[FILE] missing chunks: {missing[:8]}{'...' if len(missing) > 8 else ''}")
            del self.user.incoming_files[file_id]
            return

        # Deterministic reassembly by index, per SOCP’s indexed chunking.
        ordered = [info["buf"][i] for i in range(total)]
        data = b"".join(ordered)

        # Protocol doesn’t mandate storage location.
        # We write to the client’s downloads/ directory to finalize the transfer.
        out_path = os.path.join(self.user.files_directory, name)
        try:
            #open a file at the path in write binary mode
            with open(out_path, "wb") as wf:
                #writes the bytes in data to the file
                wf.write(data)
        except Exception as e:
            print(f"[FILE] write failed: {e}")
            del self.user.incoming_files[file_id]
            return

        # Metrics/logs
        kb = len(data)
        took = time.time() - info["ts"]
        print(f"[FILE] SAVED: {out_path} ({kb} bytes) in {took:.2f}s")
        file_name = Path(out_path).name
        print(f"[FILE] You can can open using /open {file_name}")

        # Cleanup per transfer
        del self.user.incoming_files[file_id]

    #Handles USER_ADVERTISE messages (when a new user comes online)
    async def handle_user_advertise(self, envelope: Envelope):
        uid = envelope.payload.get("user_id")
        sid = envelope.payload.get("server_id")
        meta = envelope.payload.get("meta", {}) or {}
        if uid:
            #update the client's known_users dictionary -> map the user with their server
            self.user.known_users[uid] = sid
            pub = meta.get("pubkey_b64") 
            if pub:
                self.user.known_pubkeys[uid] = pub
                logger.debug("Presence: cached pubkey for uid=%s (len=%d)", uid, len(pub))
            else:
                logger.warning("Presence: no pubkey in advertise for uid=%s meta=%s", uid, meta)

            logger.debug("User %s detected presence: %s is online at server=%s",
                        self.user.user_id, uid, sid)
            print(f"[PRESENCE] User {uid} is online.")

    #Handles USER_REMOVE (user went offline)
    async def handle_user_remove(self, envelope: Envelope):
        uid = envelope.payload.get("user_id")
        #Delete from known_users
        if uid in self.user.known_users:
            del self.user.known_users[uid]
            logger.debug("User %s detected presence removal: %s went offline",
                        self.user.user_id, uid)
            print(f"[PRESENCE] User {uid} went offline.")

    async def handle_error(self, envelope: Envelope):
        #handling error messages from server
        payload = envelope.payload
        error_code = payload.get('code', 'UNKNOWN_ERROR')
        error_detail = payload.get('detail', '')
        
        logger.debug("User %s received ERROR: code=%s detail=%s",
                     self.user.user_id, error_code, error_detail)
        
        # Handle specific error types
        if error_code == "USER_NOT_FOUND":
            print("The user you're trying to message doesn't exist or is offline")
        elif error_code == "NAME_IN_USE":
            print("Your account is already logged in elsewhere. Aborting this session.")
            # Proactively drop this user's session so the CLI returns to logged-out state
            try:
                await self.user.disconnect()
            except Exception:
                pass
        elif error_code == "INVALID_SIG":
            print("Message signature verification failed")
        elif error_code == "BAD_KEY":
            print("Cryptographic key error")
        elif error_code == "TIMEOUT":
            print("Request timed out")
        
        print()

    #Handles server acknowledments
    async def handle_ack(self, envelope: Envelope):
        payload = envelope.payload
        msg_ref = payload.get("msg_ref", "unknown")

        logger.info("User %s received ACK for %s", self.user.user_id, msg_ref)

        server_pub_b64 = payload.get("server_pub")
        if server_pub_b64:
            try:
                self.user.server_pub_obj = self.user.cryp.load_public_key_b64url(server_pub_b64)
                logger.debug("Loaded server public key (user=%s, msg_ref=%s)", self.user.user_id, msg_ref)
            except Exception:
                # Log with traceback, but don't print key material
                logger.exception(
                    "[SEC] Failed to load server public key (user=%s, msg_ref=%s, sender=%s)",
                    self.user.user_id,
                    msg_ref,
                    getattr(envelope, "sender", None),
                )

        # Handle specific acknowledgments
        if msg_ref == "USER_HELLO":
            logger.debug("User %s successfully registered with server", self.user.user_id)
            self.user.registered = True
