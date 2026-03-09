import websockets
import asyncio
import time
import uuid #to generate the unique user IDs
import logging
import os
import math
import json
import base64
from socp.modularImp.our_crytography import Cryptography
from socp.modularImp.envelope import Envelope #message wrapper
from socp.modularImp.EnvelopeType import EnvelopeType #message types
from socp.modularImp.userProtoHandler import UserProtoHandler
from cryptography.hazmat.primitives import serialization
from typing import Dict, Optional
from socp.modularImp.constant import SERVER_HOST, SERVER_PORT, BUFFER_SIZE
from socp.modularImp.logging_config import setup_logging, module_logger

# logging
setup_logging()
SILENCE = 0
logger = module_logger(__name__, silence=bool(SILENCE))

# silencing logs
logging.disable(logging.NOTSET)
logging.getLogger("asyncio").disabled = True 
logging.getLogger("websockets").disabled = True
logging.getLogger("websockets.client").disabled = True
logging.getLogger("websockets.server").disabled = True
logging.getLogger("Database").disabled = True


class User:
    def __init__(
        self,
        server_host: str,
        server_port: int,
        server_id: str,
        server_pub_obj,
        user_id: str | None = None,
        username: str | None = None,
        password: str | None = None,
        pubkey_b64: bytes | None = None,                
        privkey_store_b64: bytes | None = None,        
        created_at: str | None = None,
        
    ):
        #prepare for all the fucntions from cryptogrpahic class
        self.cryp = Cryptography()

        # server connection
        self.uri = f"ws://{server_host}:{server_port}"
        self.server_id = server_id

        # identity (prefer server-issued user id; fallback to random for safety)
        self.user_id = user_id 
        self.username = username

        self.server_pub_obj = server_pub_obj
        self.public_key_b64 = pubkey_b64
        self.public_key = self.cryp.load_public_key_b64url(pubkey_b64) 

        self.private_key = base64.b64decode(privkey_store_b64)
        self.private_key = serialization.load_pem_private_key(self.private_key, password.encode("utf-8"))
        # Enforce RSA-4096 private key
        self.cryp.require_rsa4096_private(self.private_key)

        # metadata
        self.created_at = created_at

        # presence / messaging
        self.known_users: Dict[str, str] = {}
        self.user_proto_handler = UserProtoHandler(self)

        self.known_pubkeys: Dict[str, str] = {} 

        # Public channel (shared RSA keypair across all clients on this machine)
        # Load from a persisted PEM so separate processes use the same key.
        self._init_public_channel_keys()
        self.public_channel_priv = User._public_channel_keys[0]
        self.public_channel_pub_b64 = self.cryp.export_public_key_b64url(User._public_channel_keys[1])

        # file transfer
        self.files_directory = "files"
        os.makedirs(self.files_directory, exist_ok=True)
        self.incoming_files: Dict[str, dict] = {}

        # connection state
        self.websocket = None
        self.online = False

        logger.debug("User initialized: user_id=%s username=%s server_uri=%s server_id=%s",
                    self.user_id, self.username, self.uri, self.server_id)


    # Function to help manage the user's websocket 
    async def connect(self):
        try: 
            self.websocket = await websockets.connect(self.uri)
            self.online = True
            logger.debug("User %s connected to server %s", self.user_id, self.uri)

            # Send hello handshake
            await self.send_user_hello()

            # Create listener task to prevent blocking forever
            asyncio.create_task(self.listen_for_messages())

        except Exception as e:
            logger.error("User %s failed to connect to server %s: %s", self.user_id, self.uri, e)
            self.online = False
    async def disconnect(self):
        #marks offline
        self.online = False
        #close websocket
        if self.websocket:
            await self.websocket.close()
            logger.debug("User %s disconnected", self.user_id)

    #user listening for messages, from server and user 
    async def listen_for_messages(self):
        try:
            async for message in self.websocket:
                logger.debug("User %s received RAW message: %s", self.user_id, message)
                envelope = Envelope.from_json(message)

                if self.server_pub_obj:
                    if envelope.signature:
                        ok = self.cryp.verify_transport_sig(
                            self.server_pub_obj, envelope.payload, envelope.signature
                        )
                        if not ok:
                            logger.warning(
                                "[SEC] Dropping frame with invalid transport signature "
                                "(etype=%s, sender=%s, receiver=%s, has_sig=%s)",
                                getattr(envelope, "type", None),
                                getattr(envelope, "sender", None),
                                getattr(envelope, "receiver", None),
                                True,
                            )
                            continue
                        else:
                            logger.debug(
                                "[SEC] Transport signature verified "
                                "(etype=%s, sender=%s, receiver=%s)",
                                getattr(envelope, "type", None),
                                getattr(envelope, "sender", None),
                                getattr(envelope, "receiver", None),
                            )
                    else:
                        logger.warning(
                            "[SEC] Dropping frame missing transport signature "
                            "(etype=%s, sender=%s, receiver=%s, has_sig=%s)",
                            getattr(envelope, "type", None),
                            getattr(envelope, "sender", None),
                            getattr(envelope, "receiver", None),
                            False,
                        )
                        continue

                try:
                    await self.user_proto_handler.handle_envelope(envelope)
                except Exception as e:
                    logger.exception("User %s: error in handle_envelope: %s", self.user_id, e)

        except websockets.exceptions.ConnectionClosed:
            logger.warning("Connection closed by server for user %s", self.user_id)
            self.online = False

    def sign_transport(self, envelope: Envelope):
        # Sign canonical_json(payload) with RSASSA-PSS(SHA-256); base64url(nopad)
        envelope.signature = self.cryp.sign_pss_b64(
            self.private_key,
            self.cryp.transport_sig_bytes(envelope.payload)
        )

    #user hello envelope
    async def send_user_hello(self):
        payload = {
            "pubkey_b64": self.public_key_b64
        }

        envelope = Envelope(
            EnvelopeType.USER_HELLO.value,
            self.user_id,
            self.server_id,
            payload,
            ""
        )

        await self.send_envelope(envelope)

        logger.debug("User %s sent USER_HELLO", self.user_id)


    #send a private message to another user
    async def send_direct_message(self, recipient_user_id: str, content: str):
        logger.debug(
            "DM debug: known_pubkeys=%s, recipient=%s",
            list(self.known_pubkeys.keys()), recipient_user_id
        )

        recip_pub_b64 = self.known_pubkeys.get(recipient_user_id)
        if not recip_pub_b64:
            # self.log.error(
            #     "DM ABORT: no recip_pub_b64 for to_user_id=%s | have_keys=%s | known_users=%s",
            #     recipient_user_id,
            #     list(self.known_pubkeys.keys()),
            #     {k: self.known_users.get(k) for k in list(self.known_users.keys())[:10]},
            # )
            # In tests, fail loudly instead of silently returning:
            raise RuntimeError(f"Recipient pubkey missing for {recipient_user_id}")

        recip_pub = self.cryp.load_public_key_b64url(recip_pub_b64)      
        ciphertext_b64 = self.cryp.encrypt_rsa_oaep_b64(recip_pub, content.encode("utf-8"))

        ts_ms = int(time.time() * 1000)
        # content_sig = RSASSA-PSS over SHA256(ciphertext || from || to || ts)
        digest = self.cryp.dm_content_sig_bytes(ciphertext_b64, self.user_id, recipient_user_id, ts_ms)
        content_sig_b64 = self.cryp.sign_pss_b64(self.private_key, digest)

        payload = {
            "ciphertext": ciphertext_b64,
            "sender_pub": self.public_key_b64,
            "content_sig": content_sig_b64
        }


        
        envelope = Envelope(
            EnvelopeType.MSG_DIRECT.value,
            self.user_id,
            recipient_user_id,
            payload,
            ""  
        )
        envelope.ts = ts_ms

        await self.send_envelope(envelope)
        logger.debug("User %s sent direct message to %s: %s", self.user_id, recipient_user_id, content)

    # Send a message to everyone
    async def send_public_channel_message(self, content: str):
        """Encrypt + sign a public-channel chat and send to group 'public'. Prints full debug."""
        user = self
        ts_ms = int(time.time() * 1000)

        # Encrypt under the Public Channel's RSA-4096 public key (RSA-OAEP, SHA-256)
        pc_pub = user.cryp.load_public_key_b64url(self.public_channel_pub_b64)
        ciphertext_b64 = user.cryp.encrypt_rsa_oaep_b64(pc_pub, content.encode("utf-8"))

        # End-to-end content signature over (ciphertext || from || ts)
        digest = user.cryp.public_content_sig_bytes(ciphertext_b64, user.user_id, ts_ms)
        content_sig_b64 = user.cryp.sign_pss_b64(user.private_key, digest)

        payload = {
            "ciphertext":  ciphertext_b64,
            "sender_pub":  user.public_key_b64,  # for recipients to verify your content_sig
            "content_sig": content_sig_b64
        }

        envelope = Envelope(
            EnvelopeType.MSG_PUBLIC_CHANNEL.value,  # "MSG_PUBLIC_CHANNEL"
            user.user_id,                           # from = sender user_id
            "public",                               # to   = group id for public channel
            payload,
            ""                                     
        )
        envelope.ts = ts_ms

        await user.send_envelope(envelope)

    # helpers
    def _init_public_channel_keys(self):
        """Load or create a shared public-channel RSA keypair at a fixed path.
        This allows multiple client processes to encrypt/decrypt the same group messages.
        """
        if hasattr(User, "_public_channel_keys"):
            return

        key_path = os.environ.get(
            "SOCP_PC_KEY_PATH",
            os.path.join(os.path.dirname(__file__), "public_channel_key.pem"),
        )

        priv = None
        if os.path.exists(key_path):
            try:
                with open(key_path, "rb") as rf:
                    priv = serialization.load_pem_private_key(rf.read(), password=None)
                    # Ensure RSA-4096; if not, discard and regenerate
                    try:
                        self.cryp.require_rsa4096_private(priv)
                    except Exception:
                        priv = None
            except Exception:
                priv = None

        if priv is None:
            # generate and attempt to persist
            priv, pub = self.cryp.generate_rsa_keys()
            try:
                pem = priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                with open(key_path, "wb") as wf:
                    wf.write(pem)
            except Exception:
                # Non-fatal if we cannot write; continue with in-memory key
                pass
        else:
            pub = priv.public_key()

        User._public_channel_keys = (priv, pub)


    #This is how the client relies to othe rmessages
    async def send_ack(self, original_envelope: Envelope, msg_ref: str):
        ack_payload = {"msg_ref": msg_ref}
        
        ack_envelope = Envelope(
            EnvelopeType.ACK.value,
            self.user_id,
            original_envelope.sender,
            ack_payload,
            "" 
        )
        #send back an ACK envelope referncing the original message
        await self.send_envelope(ack_envelope)

    async def send_error_response(self, to_id: str, error_code: str, detail: str = ""):
        error_payload = {
            "code": error_code,
            "detail": detail
        }
        
        error_envelope = Envelope(
            EnvelopeType.ERROR.value,
            self.user.user_id,
            to_id,
            error_payload,
            ""
        )
        await self.send_envelope(error_envelope)

    #Helper function to send any envelope
    async def send_envelope(self, envelope: Envelope):
        #if there's no WebSocket, print error and return False
        if not self.websocket:
            logger.error("User %s not connected, cannot send envelope: %s", self.user_id, envelope.type)

            return False
        #Otherwise, serialize the envelope to JSON (envelop.to_json())
        try:
            #send the JSON string through the WebSocket
            self.sign_transport(envelope)
            await self.websocket.send(envelope.to_json())
            logger.debug("User %s sent envelope: type=%s receiver=%s payload=%s",
                         self.user_id, envelope.type, envelope.receiver, envelope.payload)
            return True
        except Exception as e:
            logger.error("User %s failed to send envelope %s: %s",
                         self.user_id, envelope.type, e, exc_info=True)
            return False

    async def send_file(self, recipient_user_id: str, path: str):
        if not os.path.isfile(path):
            print("File not found")
            return

        # Resolve recipient pubkey
        recip_pub_b64 = None
        # Prefer known_pubkeys map if you split presence; fallback to known_pubkeys if you kept it
        if hasattr(self, "known_pubkeys"):
            recip_pub_b64 = self.known_pubkeys.get(recipient_user_id)

        if not recip_pub_b64:
            print("Cannot send file: unknown recipient public key. Check for online users.")
            return
        recip_pub = self.cryp.load_public_key_b64url(recip_pub_b64)

        #rsa chunk size
        rsa_chunk = self.cryp.max_rsa_oaep_plaintext_len(recip_pub)
        

        # File metadata
        file_id = str(uuid.uuid4())
        name = os.path.basename(path)
        size = os.path.getsize(path)
        total_chunks = math.ceil(size / rsa_chunk)

        start_payload = {
            "file_id": file_id,
            "name": name,
            "size": size,
            "total_chunks": total_chunks,
            "mode": "dm|public" # unncesary but needed in socp
        }
        await self.send_envelope(Envelope(
            EnvelopeType.FILE_START.value, self.user_id, recipient_user_id, start_payload, ""
        ))
        print(f"[FILE] START sent: {name} ({size} bytes) -> {recipient_user_id}")

        # FILE_CHUNK loop – READ CLEAR -> RSA-OAEP ENCRYPT -> SEND
        sent = 0
        index = 0
        with open(path, "rb") as f:
            while True:
                clear = f.read(rsa_chunk)
                if not clear:
                    break

                # RSA-OAEP(SHA-256) encrypt, returns base64url(nopad) ciphertext
                data_b64 = self.cryp.encrypt_rsa_oaep_b64(recip_pub, clear)

                chunk_payload = {
                    "file_id": file_id,
                    "index": index,
                    "ciphertext": data_b64
                }
                await self.send_envelope(Envelope(
                    EnvelopeType.FILE_CHUNK.value, self.user_id, recipient_user_id, chunk_payload, ""
                ))

                index += 1
                sent += len(clear)
                if index % 16 == 0 or sent == size:
                    print(f"[FILE] sent {sent}/{size} bytes")

        # FILE_END
        end_payload = {"file_id": file_id}
        await self.send_envelope(Envelope(
            EnvelopeType.FILE_END.value, self.user_id, recipient_user_id, end_payload, ""
        ))
        print(f"[FILE] END sent: {name}")

    async def cmd_list(self):
        print("\n--- Online Users ---")
        for uid, sid in self.known_users.items():
            #check which one is you, if it is you add the lable (you)
            label = "(you)" if uid == self.user_id else ""
            print(f"{uid} @ {sid} {label}")
        print("-------------------\n")      

    #implement the /tell (direct message) command in CLI
    async def cmd_tell(self, user_id: str, message: str):
        await self.send_direct_message(user_id, message)
    #implement the /all (public channel) command in CLI
    async def cmd_all(self, message: str):
        await self.send_public_channel_message(message)
    #implement the /file (file transfer) command in CLI 
    async def cmd_file(self, user_id: str, path:str):
        await self.send_file(user_id, path)
