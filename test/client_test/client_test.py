import unittest
import asyncio
import uuid
import inspect

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

    async def asyncTearDown(self):
        # Disconnect clients/users
        for c in getattr(self, "clients", []) or []:
            try:
                if getattr(c, "user", None) and getattr(c.user, "online", False):
                    await c.user.disconnect()
            except Exception:
                pass
            try:
                await c.disconnect()
            except Exception:
                pass

        # Cancel background server tasks
        for t in getattr(self, "background_tasks", []) or []:
            try:
                t.cancel()
            except Exception:
                pass

        # Give sockets a moment to close
        await asyncio.sleep(0.2)

    # ---------- helpers ----------
    async def _make_client(self, host: str, port: int) -> Client:
        """Create Client(), connect(host, port), track for teardown."""
        client = Client()
        await client.connect(host,port)
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


    # ---------- tests ----------
    async def test_two_clients_register_login_same_peer(self):
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

        # Server DB should now have both users
        self.assertIsNotNone(target.db.get_user_full_by_username(uname1))
        self.assertIsNotNone(target.db.get_user_full_by_username(uname2))

        self.assertTrue(await self._client_login(c1, uname1, pw1))
        self.assertTrue(await self._client_login(c2, uname2, pw2))

    async def test_two_clients_can_dm_each_other_same_peer(self):
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

        # ----- capture inbound DMs on each USER, not the client -----
        u1, u2 = c1.user, c2.user
        self.assertIsNotNone(u1.user_id)
        self.assertIsNotNone(u2.user_id)
    
        # naive: small pause
        await asyncio.sleep(0.1)
        print("u1.user_id =", u1.user_id)
        print("u2.user_id =", u2.user_id)
        print("u1.known_pubkeys keys BEFORE =", list(getattr(u1, "known_pubkeys", {}).keys()))
        print("u2.known_pubkeys keys BEFORE =", list(getattr(u2, "known_pubkeys", {}).keys()))

        async def _wait_known(u_me, u_other, label, timeout=2.0):
            loop = asyncio.get_running_loop()
            end = loop.time() + timeout
            last_dump = 0.0
            while loop.time() < end:
                keys = getattr(u_me, "known_pubkeys", {})
                if u_other.user_id in keys:
                    print(f"[{label}] READY: {u_other.user_id} in known_pubkeys")
                    return True
                # periodic progress dump
                if loop.time() - last_dump > 0.25:
                    print(f"[{label}] waiting… have={list(keys.keys())}")
                    last_dump = loop.time()
                await asyncio.sleep(0.02)
            print(f"[{label}] TIMEOUT: known_pubkeys={list(keys.keys())}, need {u_other.user_id}")
            return False

        self.assertTrue(await _wait_known(u1, u2, "u1->u2"))
        self.assertTrue(await _wait_known(u2, u1, "u2->u1"))



        # ----- act: use User.send_direct_message(recipient_user_id, content) -----
        msg_a2b = "hi bob 👋"
        msg_b2a = "hey alice ✨"

        await asyncio.gather(
            u1.send_direct_message(u2.user_id, msg_a2b),
            u2.send_direct_message(u1.user_id, msg_b2a),
        )

    async def test_two_clients_can_public_channel_same_peer(self):
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

        # ----- capture inbound Public-Channel on u2 -----
        u1, u2 = c1.user, c2.user
        self.assertIsNotNone(u1.user_id)
        self.assertIsNotNone(u2.user_id)

        got_msg = asyncio.Event()
        received = {}

        orig_handle = u2.user_proto_handler.handle_public_channel_message

        async def spy_handle_public(envelope):
            await orig_handle(envelope)  # still run real handler
            payload = envelope.payload or {}
            ct_b64 = payload.get("ciphertext")
            if ct_b64:
                # decrypt using u2’s crypto + channel key
                plaintext = u2.cryp.decrypt_rsa_oaep_b64(
                    u2.public_channel_priv, ct_b64
                ).decode("utf-8")
                received["msg"] = plaintext
                got_msg.set()

        u2.user_proto_handler.handle_public_channel_message = spy_handle_public

        # ----- act: send public message from u1 -----
        msg_text = "hello everyone 🌍"
        await u1.send_public_channel_message(msg_text)

        # ----- assert -----
        try:
            await asyncio.wait_for(got_msg.wait(), timeout=3.0)
        except asyncio.TimeoutError:
            self.fail("Timeout waiting for u2 to receive public channel message")

        self.assertEqual(received.get("msg"), msg_text)



if __name__ == "__main__":
    unittest.main()
