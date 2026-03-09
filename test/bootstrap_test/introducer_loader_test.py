import unittest
import tempfile, os, yaml
from socp.modularImp.introducerLoader import IntroducerLoader

class TestIntroducerLoader(unittest.TestCase):
    def test_load_multiple_introducers(self):
        data = {
            "introducer_servers": [
                {"host": "127.0.0.1", "port": 25001, "pubkey": "pubkey1"},
                {"host": "127.0.0.1", "port": 25002, "pubkey": "pubkey2"},
                {"host": "127.0.0.1", "port": 25003, "pubkey": "pubkey3"},
            ]
        }

        # FIX: open tempfile in text mode
        tmpfile = tempfile.NamedTemporaryFile(delete=False, suffix=".yaml", mode="w")
        yaml.dump(data, tmpfile)
        tmpfile.close()

        loader = IntroducerLoader(tmpfile.name)
        introducers = loader.load()

        os.unlink(tmpfile.name)

        self.assertEqual(len(introducers), 3)
        self.assertEqual(introducers[0]["port"], 25001)
        self.assertEqual(introducers[1]["pubkey"], "pubkey2")
        self.assertEqual(introducers[2]["host"], "127.0.0.1")

if __name__ == "__main__":
    unittest.main()