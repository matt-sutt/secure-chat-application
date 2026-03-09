import unittest
from unittest.mock import AsyncMock, patch
from socp.modularImp.envelope import Envelope
from socp.modularImp.EnvelopeType import EnvelopeType
from socp.modularImp.server import Server

class TestServerHelloJoin(unittest.IsolatedAsyncioTestCase):
    async def test_send_server_hello_join(self):
        host = "127.0.0.1"
        port = 26002
        server = Server(host,port)

        # Fake SERVER_WELCOME response
        assigned_id = "server_Y"
        welcome_env = Envelope(
            EnvelopeType.SERVER_WELCOME.value,
            "introducer_1",
            "tmpid",
            {"assigned_id": assigned_id, "clients": []},
            ""
        )

        fake_ws = AsyncMock()
        fake_ws.recv = AsyncMock(return_value=welcome_env.to_json())
        fake_connect_ctx = AsyncMock()
        fake_connect_ctx.__aenter__.return_value = fake_ws

        with patch("socp.modularImp.server.websockets.connect", return_value=fake_connect_ctx):
            success = await server.send_server_hello_join("127.0.0.1", 25001)

        self.assertTrue(success)
        self.assertEqual(server.server_id, assigned_id)



if __name__ == "__main__":
    unittest.main()