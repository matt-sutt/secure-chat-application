import unittest
import asyncio
import uuid
import inspect
import os
import tempfile
import hashlib

from socp.modularImp.server import Server
from socp.modularImp.client import Client
from socp.modularImp.envelope import Envelope
from socp.modularImp.EnvelopeType import EnvelopeType


class TestClientAuthOverCluster(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Track background tasks for servers/users/clients
        self.background_tasks = []
        self.clients = []

        # === CONFIG (matches your bootstrap flow) ===
        NUM_INTRODUCERS = 2
        NUM_PEERS = 6
        introducer_base_port = 25010
        peer_base_port = 25100

        # --- Start introducers ---
        self.introducers = []
        for i in range(NUM_INTRODUCERS):
            port = introducer_base_port + i
            introducer = Server("127.0.0.1", port)
            introducer.server_id = f"introducer_{i+1}"
            introducer.is_introducer = True
            t = asyncio.create_task(introducer.start())
            self.background_tasks.append(t)
            self.introducers.append(introducer)

        await asyncio.sleep(0.5)

        # --- Start peer servers ---
        self.peers = []
        for i in range(NUM_PEERS):
            port = peer_base_port + i
            peer = Server("127.0.0.1", port)
            t = asyncio.create_task(peer.start())
            self.background_tasks.append(t)
            self.peers.append(peer)

        await asyncio.sleep(0.5)

        # --- Peers join introducers (distribute evenly) ---
        for i, peer in enumerate(self.peers):
            intro_idx = i % NUM_INTRODUCERS  # distribute peers across introducers
            intro_host, intro_port = "127.0.0.1", introducer_base_port + intro_idx
            success = await peer.send_server_hello_join(intro_host, intro_port)
            self.assertTrue(success)

        # allow routing tables to stabilize a bit
        await asyncio.sleep(1.0)

    # ---------- helpers ----------
    async def _make_client(self, host: str, port: int) -> Client:
        """Create Client(), connect(host, port), track for teardown."""
        client = Client()
        await client.connect(host, port)
        self.clients.append(client)
        return client

    async def _client_register(self, client: Client, username: str, password: str) -> bool:
        res = await client.register(username, password)
        if isinstance(res, bool):
            return res
        if isinstance(res, dict):
            return bool(res.get("ok") or res.get("Register_Status") is True or res.get("success") is True)
        return False

    async def _client_login(self, client: Client, username: str, password: str) -> bool:
        res = await client.login(username, password)
        if isinstance(res, bool):
            return res
        if isinstance(res, dict):
            return bool(res.get("ok") or res.get("Login_Status") is True or res.get("success") is True)
        return False

    # ======= tests =======
    async def test_two_clients_can_file_transfer_same_peer(self):
        def sha256_hex(b: bytes) -> str:
            return hashlib.sha256(b).hexdigest()

        # ----- setup: same-peer register + login -----
        target = self.peers[0]

        c1 = await self._make_client("127.0.0.1", target.port)
        c2 = await self._make_client("127.0.0.1", target.port)

        uname1 = f"u1_{uuid.uuid4().hex[:6]}"
        uname2 = f"u2_{uuid.uuid4().hex[:6]}"
        pw1 = "Password1"
        pw2 = "Password2"

        self.assertTrue(await self._client_register(c1, uname1, pw1))
        self.assertTrue(await self._client_register(c2, uname2, pw2))

        await asyncio.sleep(0.2)
        self.assertIsNotNone(target.db.get_user_full_by_username(uname1))
        self.assertIsNotNone(target.db.get_user_full_by_username(uname2))

        self.assertTrue(await self._client_login(c1, uname1, pw1))
        self.assertTrue(await self._client_login(c2, uname2, pw2))

        u1, u2 = c1.user, c2.user
        self.assertIsNotNone(u1.user_id)
        self.assertIsNotNone(u2.user_id)

        # ----- make a tiny temp file -----
        payload = b"hello from u1 via file-transfer\n"
        expected_size = len(payload)
        expected_sha = sha256_hex(payload)

        tfile = tempfile.NamedTemporaryFile(prefix="socp_test_", suffix=".txt", delete=False)
        try:
            tfile.write(payload)
            tfile.flush()
            tfile.close()
            file_path = tfile.name
            file_name = os.path.basename(file_path)

            # ----- try high-level send first; else raw envelopes -----
            sent = False
            if hasattr(u1, "send_file_to_user") and callable(getattr(u1, "send_file_to_user")):
                # expected signature: await send_file_to_user(recipient_user_id, path)
                await u1.send_file_to_user(u2.user_id, file_path)
                sent = True
            elif hasattr(c1, "send_file_dm") and callable(getattr(c1, "send_file_dm")):
                # expected signature: await send_file_dm(to_user_id=..., path=...)
                await c1.send_file_dm(to_user_id=u2.user_id, path=file_path)
                sent = True
            elif hasattr(c1, "send_command") and callable(getattr(c1, "send_command")):
                # CLI-like fallback (your client may support this)
                await c1.send_command(f"/file {u2.user_id} {file_path}")
                sent = True
            else:
                # raw envelope fallback (construct FILE_START/FILE_CHUNK/FILE_END)
                sender = c1 if hasattr(c1, "send_envelope") else u1 if hasattr(u1, "send_envelope") else None
                self.assertIsNotNone(sender, "No API to send file envelopes (need send_envelope).")

                file_id = uuid.uuid4().hex

                # Build FILE_START
                start_payload = {
                    "file_id": file_id,
                    "name": file_name,
                    "size": expected_size,
                    "sha256": expected_sha,
                    "mode": "dm",
                }
                start_env = Envelope(
                    EnvelopeType.FILE_START,
                    sender=u1.user_id,
                    receiver=u2.user_id,
                    payload=start_payload,
                )
                await sender.send_envelope(start_env)

                # FILE_CHUNK — encrypt like DM if helper exists, else let client auto-encrypt
                if hasattr(c1, "encrypt_for") and callable(getattr(c1, "encrypt_for")):
                    ciphertext = await c1.encrypt_for(u2.user_id, payload)
                elif hasattr(u1, "encrypt_for") and callable(getattr(u1, "encrypt_for")):
                    ciphertext = await u1.encrypt_for(u2.user_id, payload)
                else:
                    # If your pipeline auto-encrypts at send_envelope, plaintext is acceptable.
                    ciphertext = payload

                chunk_payload = {"file_id": file_id, "index": 0, "ciphertext": ciphertext}
                chunk_env = Envelope(
                    EnvelopeType.FILE_CHUNK,
                    sender=u1.user_id,
                    receiver=u2.user_id,
                    payload=chunk_payload,
                )
                await sender.send_envelope(chunk_env)

                end_env = Envelope(
                    EnvelopeType.FILE_END,
                    sender=u1.user_id,
                    receiver=u2.user_id,
                    payload={"file_id": file_id},
                )
                await sender.send_envelope(end_env)
                sent = True

            self.assertTrue(sent, "Failed to send file by any available API")

            # ----- wait until received & verify by size + sha256 -----
            async def received_ok() -> bool:
                # 1) If the receiver exposes a completed-file list:
                if hasattr(u2, "received_files"):
                    try:
                        for rec in u2.received_files:  # type: ignore[attr-defined]
                            name = rec.get("name")
                            size = rec.get("size")
                            sha = rec.get("sha256") or rec.get("sha")
                            if name == file_name and size == expected_size and sha == expected_sha:
                                return True
                    except Exception:
                        pass

                # 2) If the client or user writes to a download dir:
                ddir = None
                if hasattr(c2, "download_dir"):
                    ddir = getattr(c2, "download_dir")
                elif hasattr(u2, "download_dir"):
                    ddir = getattr(u2, "download_dir")
                if ddir:
                    out = os.path.join(ddir, file_name)
                    if os.path.exists(out) and os.path.getsize(out) == expected_size:
                        with open(out, "rb") as fh:
                            if sha256_hex(fh.read()) == expected_sha:
                                return True

                # 3) If the receiver exposes a last_file_received-like dict:
                for attr in ("last_file_received", "last_received_file", "last_completed_file"):
                    if hasattr(u2, attr):
                        info = getattr(u2, attr)
                        if isinstance(info, dict):
                            if (
                                info.get("name") == file_name and
                                info.get("size") == expected_size and
                                (info.get("sha256") == expected_sha or info.get("sha") == expected_sha)
                            ):
                                return True
                return False

            end_time = asyncio.get_event_loop().time() + 8.0
            ok = False
            while asyncio.get_event_loop().time() < end_time:
                if await received_ok():
                    ok = True
                    break
                await asyncio.sleep(0.05)

            self.assertTrue(ok, "Receiver did not confirm file receipt (size/hash mismatch or no record)")

        finally:
            try:
                os.unlink(tfile.name)
            except Exception:
                pass

    async def asyncTearDown(self):
        # Disconnect clients if they expose a coroutine disconnect()
        for cli in self.clients:
            disc = getattr(cli, "disconnect", None)
            if disc and inspect.iscoroutinefunction(disc):
                try:
                    await disc()
                except Exception:
                    pass

        # Cancel servers
        for t in self.background_tasks:
            t.cancel()
        for t in self.background_tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    unittest.main()
