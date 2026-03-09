import unittest
import asyncio
import uuid
import inspect

from socp.modularImp.server import Server
from socp.modularImp.serverProtoHandler import ServerProtocolHandler
from socp.modularImp.envelope import Envelope
from socp.modularImp.EnvelopeType import EnvelopeType
from socp.modularImp.user import User

class TestBroadcastUserRemove(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        # Track background tasks for servers/users
        self.background_tasks = []

        # === CONFIG ===
        NUM_INTRODUCERS = 2
        NUM_PEERS = 6
        USERS_PER_SERVER = 3
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

        # --- Add users across *all* servers ---
        self.users = []
        self.listeners = []

        all_servers = self.introducers + self.peers

        for server in all_servers:
            for _ in range(USERS_PER_SERVER):
                # ✅ Use new User(host, port) signature
                u = User("127.0.0.1", server.port, server.server_id)  
                await u.connect()
                self.users.append(u)


        await asyncio.sleep(1.5)  # allow gossip/presence propagation


    # === NEW TEST 1: broadcast user remove within the same introducer network ===
    async def test_broadcast_user_remove_same_introducer_network(self):
        """
        Choose a user that lives on peer_0 (which is under introducer_1) and
        broadcast USER_REMOVE only to introducer_1's network:
        [introducer_1, peer_0, peer_2, peer_4].
        All of these servers should drop the mapping for that uid.
        """
        introducer1 = self.introducers[0]
        network_servers = [introducer1, self.peers[0], self.peers[2], self.peers[4]]
        announcer = self.peers[0]

        # Find a uid that announcer believes it owns.
        uid = None
        for k, v in getattr(announcer, "user_location", {}).items():
            if v == announcer.server_id:
                uid = k
                break

        # If not found immediately, try to resolve from connected users on announcer
        if uid is None:
            candidates = [u.user_id for u in self.users if u.uri.endswith(str(announcer.port))]
            self.assertTrue(candidates, f"No users found connected to {announcer.server_id}")
            # wait briefly for announcer.user_location to reflect local ownership
            deadline = asyncio.get_event_loop().time() + 1.0
            while uid is None and asyncio.get_event_loop().time() < deadline:
                for k, v in getattr(announcer, "user_location", {}).items():
                    if v == announcer.server_id and k in candidates:
                        uid = k
                        break
                if uid is None:
                    await asyncio.sleep(0.05)

        self.assertIsNotNone(uid, f"No user mapped to {announcer.server_id} on its own server")

        # Build USER_REMOVE from the true owner
        env = Envelope(
            EnvelopeType.USER_REMOVE.value,
            sender=announcer.server_id,
            receiver="*",
            payload={"user_id": uid, "server_id": announcer.server_id},
            sig=""
        )

        # Deliver ONLY to the same-introducer network
        for s in network_servers:
            if not hasattr(s, "proto_handler") or s.proto_handler is None:
                s.proto_handler = ServerProtocolHandler(s)
            await s.proto_handler.handle_user_remove(env)

        # Everyone in this network should have removed the mapping
        for s in network_servers:
            self.assertNotIn(
                uid, getattr(s, "user_location", {}),
                f"{s.server_id} (same introducer network) should have removed {uid}"
            )

    # === NEW TEST 2: local-only user remove on the same peer server ===
    async def test_broadcast_user_remove_same_peer_server_local(self):
        """
        Choose a user owned by peer_0 and send USER_REMOVE only to peer_0 (no broadcast).
        peer_0 should remove its local mapping. Other servers in the same introducer network
        should remain unchanged unless they also receive the envelope.
        """
        introducer1 = self.introducers[0]
        network_servers = [introducer1, self.peers[0], self.peers[2], self.peers[4]]
        local_server = self.peers[0]

        # Pick a locally owned uid on the target peer
        uid = None
        for k, v in getattr(local_server, "user_location", {}).items():
            if v == local_server.server_id:
                uid = k
                break

        if uid is None:
            candidates = [u.user_id for u in self.users if u.uri.endswith(str(local_server.port))]
            self.assertTrue(candidates, f"No users found connected to {local_server.server_id}")
            deadline = asyncio.get_event_loop().time() + 1.0
            while uid is None and asyncio.get_event_loop().time() < deadline:
                for k, v in getattr(local_server, "user_location", {}).items():
                    if v == local_server.server_id and k in candidates:
                        uid = k
                        break
                if uid is None:
                    await asyncio.sleep(0.05)

        self.assertIsNotNone(uid, f"No user mapped to {local_server.server_id} on its own server")

        # Local-only USER_REMOVE (deliver only to the local server)
        env = Envelope(
            EnvelopeType.USER_REMOVE.value,
            sender=local_server.server_id,
            receiver="*",
            payload={"user_id": uid, "server_id": local_server.server_id},
            sig=""
        )

        if not hasattr(local_server, "proto_handler") or local_server.proto_handler is None:
            local_server.proto_handler = ServerProtocolHandler(local_server)

        await local_server.proto_handler.handle_user_remove(env)

        # Local server must remove
        self.assertNotIn(
            uid, getattr(local_server, "user_location", {}),
            f"{local_server.server_id} should have removed {uid} locally"
        )

        # Others in the same introducer network should be unchanged
        for s in network_servers:
            if s is local_server:
                continue
            loc = getattr(s, "user_location", {})
            # If they DO have the uid (from prior presence), it should still
            # point at the local server since they weren't told about the removal.
            if uid in loc:
                self.assertEqual(
                    loc[uid], local_server.server_id,
                    f"{s.server_id} should remain unchanged for {uid} without receiving USER_REMOVE"
                )

if __name__ == "__main__":
    unittest.main()
