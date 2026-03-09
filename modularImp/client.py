import websockets
import asyncio
import uuid
import os
import base64
import logging
from .envelope import Envelope
from .EnvelopeType import EnvelopeType
from .user import User
from socp.modularImp.our_crytography import Cryptography
from socp.modularImp.logging_config import setup_logging, module_logger

setup_logging()  # set up logging
SILENCE = 0  # silence flag

#logging
logger = module_logger(__name__, silence=bool(SILENCE))  

# silence logging
logging.disable(logging.NOTSET)  
logging.getLogger("asyncio").disabled = True  
logging.getLogger("websockets").disabled = True 
logging.getLogger("websockets.client").disabled = True  
logging.getLogger("websockets.server").disabled = True 
logging.getLogger("Database").disabled = True  

class Client:
    def __init__(self,autostart_cli: bool = False):
        self.websocket = None  # websocket handle
        self.client_id = str(uuid.uuid4())  # unique client id
        self.client_online = False  # connection state

        # set after connect()
        self.host: str | None = None  # server host
        self.port: int | None = None  # server port
        self.uri: str | None = None  # websocket uri
        self.cryp = Cryptography()  # crypto helper
        # server id is unknown before first response, we start with "*"
        self.server_id: str | None = None  # server id

        self.user = None  # user session
        self.user_id = None  # user id cache
        self.username: str | None = None      # username cache
        self.autostart_cli = autostart_cli    # autostart cli flag
        self._cli_task: asyncio.Task | None = None  # cli task

        logger.debug(
            "[Client.__init__] client_id=%s initial_server_id=%s",
            self.client_id, self.server_id
        )

    # lifecycle 
    async def wait(self):
        if self._cli_task is not None:  # wait for cli
            try:
                await self._cli_task  # await task
            finally:
                self._cli_task = None  # clear handle

    async def connect(self, host: str, port: int):
        self.host = host  # save host
        self.port = port  # save port
        self.uri = f"ws://{host}:{port}"  # build uri
        try:
            self.websocket = await websockets.connect(self.uri)  # connect
            self.client_online = True  # mark online
            logger.debug("[connect] Connected to %s", self.uri)

        except Exception as e:
            logger.error("[connect] Connection failed to %s: %s", self.uri, e, exc_info=True)
            raise  # rethrow

    async def disconnect(self):
        if self.websocket:
            try:
                await self.websocket.close()  # close socket
            except Exception as e:
                logger.error("disconnect] Error closing websocket: %s", e, exc_info=True)
        self.client_online = False  # mark offline
        logger.debug("[disconnect] Disconnected")
        print("Disconnected from server.")

    # core io 

    async def send_envelope(self, envelope: Envelope) -> bool:
        if not self.websocket:  # must be connected
            logger.error("[Client.send_envelope] Not connected")
            return False
        try:
            msg = envelope.to_json()  # serialize
            logger.debug("[Client.send_envelope] -> %s", msg)
            await self.websocket.send(msg)  # send text
            return True
        except Exception as e:
            logger.error("[Client.send_envelope] send failed: %s", e, exc_info=True)
            return False

    async def _recv_envelope(self) -> Envelope:
        raw = await self.websocket.recv()  # receive text
        logger.debug("[Client._recv_envelope] <- %s", raw)
        return Envelope.from_json(raw)  # parse json

    # helpers

    def _hydrate_user_from_payload(self, info: dict, server_block: dict | None, password: str):
        if isinstance(server_block, dict):  # update server info
            sid = server_block.get("server_id")
            if sid:
                self.server_id = sid  # set server id
            if server_block.get("host"):
                self.host = self.host or server_block["host"]  # fill host
            if server_block.get("port"):
                self.port = self.port or server_block["port"]  # fill port
            if self.host and self.port:
                self.uri = f"ws://{self.host}:{self.port}"  # rebuild uri
            if server_block.get("pubkey"):
                self.server_pub_b64 = server_block["pubkey"]  # server key b64
                self.server_pub_obj = self.cryp.load_public_key_b64url(self.server_pub_b64)  # load key

        priv = info.get("privkey_store_b64")
        if not priv:
            raise ValueError("REGISTER response missing privkey_store")  # required

        # Always (re)construct a fresh User from the profile
        self.user = User(
            server_host=self.host,
            server_port=self.port,
            server_id=self.server_id,
            server_pub_obj=self.server_pub_obj,
            user_id=info.get("user_id"),
            username=info.get("username"),
            password=password,
            pubkey_b64=info.get("pubkey_b64"),
            privkey_store_b64=info.get("privkey_store_b64"),
            created_at=info.get("created_at"),
        )

        # expose for tests
        self.user_id = self.user.user_id  # cache id
        self.username = info.get("username")  # cache name

        def _iter_dict_payload(block, key_uid="uid", key_val="sid"):
            if isinstance(block, dict):
                block_iter = [block]
            elif isinstance(block, list):
                block_iter = block
            else:
                return []
            normalized = []
            for entry in block_iter:
                if not isinstance(entry, dict):
                    continue
                uid = entry.get(key_uid)
                val = entry.get(key_val)
                if uid and val:
                    normalized.append((uid, val))
            return normalized

        known_users_block = server_block.get("known_users") if isinstance(server_block, dict) else None

        for uid, sid in _iter_dict_payload(known_users_block, key_uid="uid", key_val="sid"):
            self.user.known_users[uid] = sid

        known_pubkeys_block = server_block.get("known_pubkeys") if isinstance(server_block, dict) else None
        for uid, pubkey in _iter_dict_payload(known_pubkeys_block, key_uid="uid", key_val="pubkey"):
            self.user.known_pubkeys[uid] = pubkey

        # Ensure we always include our own presence so /list shows at least ourselves
        try:
            if self.user and self.user.user_id and self.server_id:
                if self.user.user_id not in self.user.known_users:
                    self.user.known_users[self.user.user_id] = self.server_id
        except Exception:
            pass 

        logger.debug(
            "[Client] hydrated user: uid=%s username=%s pubkey_len=%s priv_blob_len=%s created_at=%s server_id=%s",
            self.user.user_id,
            self.user.username,
            (len(self.user.public_key_b64) if isinstance(self.user.public_key_b64, str) else None),
            (len(self.user.privkey_store_b64) if getattr(self.user, 'privkey_store_b64', None) else 0),
            self.user.created_at,
            self.server_id
        )

    # auth flows 

    async def register(self, username: str, password: str):
        """
        Send REGISTER. Expects server to reply with:
          {
            "status": "success",
            "user": {
              "user_id", "username", "pubkey_b64", "privkey_store_b64", "created_at"
            },
            "server": { "server_id", "host", "port" }
          }
        """
        logger.debug("[Client.register] BEGIN username=%s password=%s", username, password)
        try:
            recv = self.server_id or "*"  # target server
            payload = {"username": username, "password": password}  # credentials
            env = Envelope(EnvelopeType.REGISTER.value, self.client_id, recv, payload, sig="")  # envelope

            ok = await self.send_envelope(env)  # send request
            if not ok:
                print("[register] Unable to contact the server. Please try again.")
                return False

            while True:
                resp = await self._recv_envelope()  # wait reply
                logger.debug("[Client.register] <- type=%s payload=%s", resp.type, resp.payload)

                if resp.type != EnvelopeType.REGISTER_RESPONSE.value:
                    continue  # ignore others

                status = resp.payload.get("status")
                if status != "success":
                    err = resp.payload.get("error") or "unknown error"
                    logger.debug("[Client.register] FAIL username=%s error=%s",
                                   username, err)
                    print(f"[register] Registration failed with error: {err}.")
                    print("[register] Password must be at least 8 characters long and contain a mix of uppercase letters, lowercase letters, numbers, and special characters.")
                    return False

                info = resp.payload.get("user") or {}  # user block
                server_block = resp.payload.get("server") or {}  # server block
                self._hydrate_user_from_payload(info, server_block,password)  # build user
                display_name = info.get("username") or username
                logger.debug("[Client.register] SUCCESS username=%s uid=%s", username, self.user_id)
                print(f"[register] Registration successful. Profile created for {display_name}.")
                return True

        except Exception as e:
            logger.error("[Client.register] EXCEPTION: %s", e, exc_info=True)
            print(f"[register] Unexpected error: {e}. Please try again.")
            return False

    # Method to send the log in information 
    async def login(self, username: str, password: str):
        """
        Send LOGIN. Expects server to reply with the same payload shape as register().
        """
        logger.debug("[Client.login] BEGIN username=%s password=%s", username, password)
        try:
            recv = self.server_id or "*"  # target server
            payload = {"username": username, "password": password}  # credentials
            env = Envelope(EnvelopeType.LOGIN.value, self.client_id, recv, payload, sig="")  # envelope

            ok = await self.send_envelope(env)  # send request
            if not ok:
                print("[login] Unable to contact the server. Please try again")
                return False

            while True:
                resp = await self._recv_envelope()  # wait reply
                logger.debug("[Client.login] <- type=%s payload=%s", resp.type, resp.payload)

                if resp.type != EnvelopeType.LOGIN_RESPONSE.value:
                    continue  # ignore others

                status = resp.payload.get("status")
                if status != "success":
                    err = resp.payload.get("error") or "unknown error"
                    logger.warning("[Client.login] FAIL username=%s error=%s",
                                   username, err)
                    print(f"[login] Login failed: {err}.")
                    return False

                info = resp.payload.get("user") or {}  # user block
                server_block = resp.payload.get("server") or {}  # server block
                self._hydrate_user_from_payload(info, server_block,password)  # build user

                await self.user.connect()  # start user stream (sends USER_HELLO)
                # Briefly wait to detect immediate rejection (e.g., NAME_IN_USE)
                try:
                    await asyncio.sleep(0.3)
                except Exception:
                    pass
                if not getattr(self.user, "online", False):
                    # Session was rejected/closed during hello handshake. Clear cached identity.
                    self.user = None
                    self.user_id = None
                    self.username = None
                    print("[login] Login rejected: account already active elsewhere. Please disconnect the other session.")
                    return False

                logger.debug("[Client.login] SUCCESS username=%s uid=%s", username, self.user_id)
                print(f"[login] Login successful. Welcome back, {self.username}.")
                return True

        except Exception as e:
            logger.error("[Client.login] EXCEPTION: %s", e, exc_info=True)
            print(f"[login] Unexpected error: {e}. Please try again.")
            return False

    # cli loop
    async def cli_loop(self):
        print(
            "Commands:\n"
            "  Registration & Login:\n"
            "  /register <username> <password>\n"
            "  /login <username> <password>\n"
            "\n"
            "  Messaging:\n"
            "  /tell <user_id> <message>\n"
            "  /all <message>\n"
            "\n"
            "  File transfer:\n"
            "  /file <user_id> <path>\n"
            "  /open <filename>\n"
            "\n"
            "  User Presence:\n"
            "  /list\n"
            "  /whoami\n"
            "\n"
            "  Exit application:\n"
            "  /disconnect\n"
            "  /quit\n"

        )

        loop = asyncio.get_event_loop()  # get event loop
        while self.client_online:
            try:
                line = await loop.run_in_executor(None, input, "> ")  # read input
            except (EOFError, KeyboardInterrupt):
                line = "/quit"  # exit on interrupt

            cmd = (line or "").strip()  # normalize input
            if not cmd:
                continue

            # derive login state once per turn
            logged_in = bool(self.user and getattr(self.user, "online", False))

            if cmd in ("/quit", "/exit"):
                await self.disconnect()  # close connection
                break

            if cmd.startswith("/disconnect"):
                await self.disconnect()  # close connection
                break

            if cmd.startswith("/whoami"):
                ident = self.user_id or f"guest:{self.client_id}"  # id string
                uname = self.username or "(guest)"  # name string
                if uname == "(guest)":
                    print(f"user_id={ident}. You are not logged in. Use /register or /login.")
                    continue
                print(f"user_id={ident} username={uname} server_id={self.server_id}")
                continue

            # quick help
            if cmd in ("/help", "help", "?"):
                if logged_in:
                    print(
                        "Commands (logged in):\n"
                        "  /tell <user_id> <message>\n"
                        "  /all <message>\n"
                        "  /file <user_id> <path>\n"
                        "  /open <filename>\n"
                        "  /list\n"
                        "  /whoami\n"
                        "  /disconnect\n"
                        "  /quit\n"
                    )
                else:
                    print(
                        "Commands (not logged in):\n"
                        "  /register <username> <password>\n"
                        "  /login <username> <password>\n"
                        "  /whoami\n"
                        "  /quit\n"
                    )
                continue

            if cmd.startswith("/register "):
                parts = cmd.split()
                if len(parts) < 3:
                    print("Usage: /register <username> <password>")
                    continue
                if logged_in:
                    ident = self.username or self.user_id or f"guest:{self.client_id}"
                    print(f"Already logged in as {ident}. Use /disconnect first.")
                    continue
                ok = await self.register(parts[1], parts[2])  # run register
                continue
            
            if cmd.startswith("/login "):
                parts = cmd.split()
                if len(parts) < 3:
                    print("Usage: /login <username> <password>")
                    continue
                if logged_in:
                    ident = self.username or self.user_id or f"guest:{self.client_id}"
                    print(f"Already logged in as {ident}. Use /disconnect first.")
                    continue
                ok = await self.login(parts[1], parts[2])  # run login
                continue

            # require login for messaging, files, and presence listing
            if self.user and logged_in:

                if cmd.startswith("/tell "):
                    parts = cmd.split(" ", 2)
                    if len(parts) < 3:
                        print("Usage: /tell <user_id> <message>")
                        continue

                    recipient_id = parts[1]
                    message = parts[2]

                    # Basic recipient validation: ensure UUID format
                    try:
                        uuid.UUID(recipient_id)
                    except Exception:
                        print("Invalid user_id format. Expected a UUID.")
                        continue

                    # Ensure we have a pubkey for the recipient before attempting send
                    try:
                        has_key = bool(self.user.known_pubkeys.get(recipient_id))
                    except Exception:
                        has_key = False

                    if not has_key:
                        print("Cannot send: unknown recipient or missing public key. Use /list to see known users.")
                        continue

                    try:
                        await self.user.send_direct_message(recipient_id, message)  # send dm
                    except RuntimeError as e:
                        text = str(e)
                        if "Recipient pubkey missing" in text:
                            print("Cannot send: recipient public key is not available. Ensure the user is online and known (/list).")
                            continue
                        else:
                            print(f"Failed to send DM: {text}")
                            continue
                    continue

                if cmd.startswith("/all "):
                    await self.user.send_public_channel_message(cmd[5:])  # broadcast
                    continue

                if cmd == "/list":
                    await self.user.cmd_list()  # list users
                    continue

                if cmd.startswith("/open "):
                    parts = cmd.split(" ", 1)
                    if len(parts) < 2:
                        print("Usage: /open <filename>")
                        continue
                    fname = parts[1]
                    path = os.path.join(self.user.files_directory, fname)  # build path
                    if not os.path.exists(path):
                        print(f"[OPEN] File not found: {path}")
                        continue
                    import subprocess, sys
                    if sys.platform.startswith("darwin"):
                        subprocess.run(["open", path])  # mac open
                    elif sys.platform.startswith("win"):
                        os.startfile(path)  # windows open
                    else:
                        subprocess.run(["xdg-open", path])  # linux open
                    continue

                if cmd.startswith("/file "):
                    # /file <user_id> <path>  (path may contain spaces)
                    parts = cmd.split(" ", 2)
                    if len(parts) < 3:
                        print("Usage: /file <user_id> <path>")
                    else:
                        recipient = parts[1]
                        path = parts[2]

                        # Validate recipient format (UUID)
                        try:
                            uuid.UUID(recipient)
                        except Exception:
                            print("Invalid user_id format. Expected a UUID.")
                            continue

                        # Ensure we have a pubkey for the recipient
                        try:
                            has_key = bool(self.user.known_pubkeys.get(recipient))
                        except Exception:
                            has_key = False

                        if not has_key:
                            print("Cannot send file: unknown recipient or missing public key. Use /list to see known users.")
                            continue

                        # Validate file path before attempting send
                        if not os.path.isfile(path):
                            print("File not found. Please provide a valid path.")
                            continue

                        try:
                            await self.user.cmd_file(recipient, path)  # send file
                        except RuntimeError as e:
                            text = str(e)
                            if "Recipient pubkey missing" in text:
                                print("Cannot send file: recipient public key is not available. Ensure the user is online and known (/list).")
                            else:
                                print(f"Failed to send file: {text}")
                    continue

            # fallbacks
            guarded = (cmd.startswith("/tell ") or cmd.startswith("/all ") or
                       cmd.startswith("/file ") or cmd.startswith("/open ") or
                       cmd == "/list")
            if guarded and not logged_in:
                print("You must be logged in to use this command.")
                continue

            print("Unknown command. Type /help")
