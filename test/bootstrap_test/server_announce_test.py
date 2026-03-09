import asyncio
import unittest
from unittest.mock import AsyncMock
from socp.modularImp.server import Server


from socp.modularImp.serverProtoHandler import ServerProtocolHandler
from socp.modularImp.envelope import Envelope
from socp.modularImp.EnvelopeType import EnvelopeType

class TestServerAnnounce(unittest.IsolatedAsyncioTestCase):
    async def test_send_server_announce(self):
        host = "127.0.0.1"
        port = 26001
        server = Server(host,port)
        server.server_id = "server_X"

        fake_ws = AsyncMock()
        server.servers = {"peer1": fake_ws}

        # Call announce
        await server.send_server_announce()

        # Verify envelope was sent once
        fake_ws.send.assert_awaited()




class DummyServer:
    def __init__(self):
        self.server_id = "introducer_1"
        self.server_addrs = {}

class TestHandleServerAnnounce(unittest.IsolatedAsyncioTestCase):
    async def test_handle_server_announce(self):
        dummy_server = DummyServer()
        handler = ServerProtocolHandler(dummy_server)

        announce_env = Envelope(
            EnvelopeType.SERVER_ANNOUNCE.value,
            "server_X",
            "*",
            {"host": "127.0.0.1", "port": 26001, "pubkey": "TESTKEY"},
            ""
        )

        await handler.handle_server_announce(announce_env)
        self.assertIn("server_X", dummy_server.server_addrs)




if __name__ == "__main__":
    unittest.main()