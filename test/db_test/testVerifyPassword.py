import unittest
import tempfile
import os
from socp.modularImp.db import DatabaseManager


class TestVerifyPassword(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmpdir.name, "test_verify.db")
        self.db = DatabaseManager(db_path=self.db_path)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_verify_correct_password(self):
        stored = self.db.hash_password("Abcdef12")
        self.assertTrue(self.db.verify_password("Abcdef12", stored))

    def test_verify_wrong_password(self):
        stored = self.db.hash_password("Abcdef12")
        self.assertFalse(self.db.verify_password("NotIt999", stored))

if __name__ == "__main__":
    unittest.main()
