import unittest
import asyncio
import time

from socp.modularImp.server import Server

# Override intervals for faster testing
TEST_HEARTBEAT_INTERVAL = 1      # 1 second between heartbeats
TEST_HEARTBEAT_TIMEOUT = 3       # consider peer dead after 3 seconds


class TestMultiServerHeartbeat(unittest.IsolatedAsyncioTestCase):

    async def asyncSetUp(self):
        self.background_tasks = []
        self.servers = []

        base_port = 27000

        # Start 3 servers
        for i in range(3):
            srv = Server("127.0.0.1", base_port + i)
            srv.server_id = f"server_{i+1}"
            srv.enable_heartbeat = True
            # override constants for testing speed
            srv.HEARTBEAT_INTERVAL = TEST_HEARTBEAT_INTERVAL
            srv.HEARTBEAT_TIMEOUT = TEST_HEARTBEAT_TIMEOUT
            t = asyncio.create_task(srv.start())
            self.background_tasks.append(t)
            self.servers.append(srv)

        # wait for servers to start
        await asyncio.sleep(0.5)

        # Make them join each other (partial mesh)
        for i, srv in enumerate(self.servers):
            for j, peer in enumerate(self.servers):
                if i != j:
                    await srv.send_server_hello_join(peer.host, peer.port, introducer_id=peer.server_id)

        # wait for introductions + ANNOUNCE
        await asyncio.sleep(1.0)

    async def asyncTearDown(self):
        for t in self.background_tasks:
            t.cancel()
        for t in self.background_tasks:
            try:
                await t
            except asyncio.CancelledError:
                pass

    async def test_heartbeat_updates_last_seen(self):
        """ Servers should exchange heartbeats and update server_last_seen dicts. """

        await asyncio.sleep(TEST_HEARTBEAT_INTERVAL * 3)  # allow some heartbeats

        now = int(time.time() * 1000)

        srv1, srv2, srv3 = self.servers

        # Each server last_seen should include all others
        for (src, dst) in [(srv1, srv2), (srv1, srv3),
                           (srv2, srv1), (srv2, srv3),
                           (srv3, srv1), (srv3, srv2)]:
            seen_ts = src.server_last_seen.get(dst.server_id, 0)
            delta = now - seen_ts
            self.assertLessEqual(
                delta, TEST_HEARTBEAT_TIMEOUT * 1000,
                f"{src.server_id} did not see heartbeat from {dst.server_id} in time"
            )

        print("\n--- Heartbeat Update Test ---")
        for s in self.servers:
            print(s.server_id, "last_seen:", s.server_last_seen)

    async def test_heartbeat_timeout_detection(self):
        """ If one server stops, others should detect a missed heartbeat. """

        srv1, srv2, srv3 = self.servers

        # Cancel server3 (simulate crash)
        task_srv3 = self.background_tasks.pop()
        task_srv3.cancel()
        try:
            await task_srv3
        except asyncio.CancelledError:
            pass

        # Wait longer than timeout
        await asyncio.sleep(TEST_HEARTBEAT_TIMEOUT + 1)

        now = int(time.time() * 1000)
        last_seen_srv3 = srv1.server_last_seen.get(srv3.server_id, 0)
        age = now - last_seen_srv3

        self.assertGreater(
            age, TEST_HEARTBEAT_TIMEOUT * 1000,
            "srv1 should detect srv3 as stale"
        )

        print("\n--- Heartbeat Timeout Test ---")
        print(f"srv1 last saw srv3 {age}ms ago (> timeout {TEST_HEARTBEAT_TIMEOUT*1000}ms)")


if __name__ == "__main__":
    unittest.main()