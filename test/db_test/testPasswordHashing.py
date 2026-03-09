import unittest
import tempfile
import os
from socp.modularImp.db import DatabaseManager


class TestPasswordHashing(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmpdir.name, "test_hash.db")
        self.db = DatabaseManager(db_path=self.db_path)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_hash_format(self):
        stored = self.db.hash_password("MyPass123")
        self.assertIn(":", stored, "Expected 'salt:hash' format")
        salt_hex, hash_hex = stored.split(":", 1)
        self.assertTrue(len(salt_hex) > 0)
        self.assertEqual(len(hash_hex), 64, "PBKDF2-SHA256 hex should be 64 chars")

    def test_verify_true_false(self):
        stored = self.db.hash_password("MyPass123")
        self.assertTrue(self.db.verify_password("MyPass123", stored))
        self.assertFalse(self.db.verify_password("WrongPass", stored))

    def test_random_salt_changes_hash(self):
        a = self.db.hash_password("SamePass123")
        b = self.db.hash_password("SamePass123")
        # very likely different because of random 16-byte salt
        self.assertNotEqual(a, b)

if __name__ == "__main__":
    unittest.main()