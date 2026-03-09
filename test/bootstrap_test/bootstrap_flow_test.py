import unittest
import asyncio
from socp.modularImp.server import Server
from socp.modularImp.user import User
import time
import uuid



class TestClusterBootstrap(unittest.IsolatedAsyncioTestCase):
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
                # Stable, human-readable id is handy in logs:
                uid = f"u_{server.server_id}_{uuid.uuid4().hex[:8]}"
                u = User(
                    "127.0.0.1",
                    server.port,
                    server.server_id,
                    user_id=uid,          # ← give the user a unique id now
                    username=uid          # (optional) mirror as username for easier debugging
                )
                await u.connect()         # USER_HELLO will now use this uid
                self.users.append(u)



        await asyncio.sleep(1.5)  # allow gossip/presence propagation

    async def test_cluster_message_exchange_same_introducer(self):
        """
        Pick two users connected under the *same introducer network*,
        send a message, and check presence is updated cluster-wide.
        """
        # User A: first user attached directly to introducer_1
        userA = self.users[0]

        # Find a user attached to one of introducer_1's peers (e.g., server_3)
        # introducer_1 manages peer_0, peer_2, peer_4
        userB = None
        introducer1_ports = [self.introducers[0].port,
                             self.peers[0].port,
                             self.peers[2].port,
                             self.peers[4].port]

        for u in self.users:
            if u.uri.endswith(str(self.peers[2].port)):
                userB = u
                break

        self.assertIsNotNone(userB, "No user found on server_3 (peer_2) under introducer_1")

        msg = "Hello within the same introducer network!"
        print("DEBUG TEST: sending from", userA.user_id, "to", userB.user_id, "userA.uri=", userA.uri, "userB.uri=", userB.uri, flush=True)
        await userA.send_direct_message(userB.user_id, msg)

        await asyncio.sleep(2.0)  # let gossip propagate fully

        print("DEBUG TEST: send_direct_message returned", flush=True)

        print("\n=== Same Introducer Test ===")
        print(f"Introducer1 port: {self.introducers[0].port}, Peer server ports: {introducer1_ports[1:]}")
        print(f"UserA ({userA.user_id}) on {userA.uri}")
        print(f"UserB ({userB.user_id}) on {userB.uri}")
        for i, u in enumerate(self.users, start=1):
            print(f"User{i} ({u.user_id}) sees: {list(u.known_users.keys())}")

    async def test_direct_message_same_server(self):
        """
        Pick two users on the *same server*, send a message,
        and ensure direct delivery works locally without forwarding.
        """
        # Find two users on the same peer server (e.g., peer_0 under introducer_1)
        target_port = self.peers[0].port
        same_server_users = [u for u in self.users if u.uri.endswith(str(target_port))]

        self.assertGreaterEqual(len(same_server_users), 2, "Not enough users on the same server to test")

        userA, userB = same_server_users[0], same_server_users[1]

        msg = "Hello from same server!"
        print("DEBUG TEST: sending from", userA.user_id, "to", userB.user_id, "on server", userA.uri, flush=True)
        await userA.send_direct_message(userB.user_id, msg)
        print("DEBUG TEST: send_direct_message returned", flush=True)
        await asyncio.sleep(0.5)  # minimal wait since delivery is local

        # UserB should see A in known users and message delivered
        self.assertIn(userA.user_id, userB.known_users)

        print("\n=== Same Server Test ===")
        print(f"Testing between UserA ({userA.user_id}) and UserB ({userB.user_id}) on server at {target_port}")
        for i, u in enumerate(same_server_users, start=1):
            print(f"User{i} ({u.user_id}) sees: {list(u.known_users.keys())}")


    async def asyncTearDown(self):
        # Disconnect users
        for u in self.users:
            await u.disconnect()

        # Cancel all tasks
        for t in self.background_tasks:
            t.cancel()
        for t in self.background_tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass


if __name__ == "__main__":
    unittest.main()