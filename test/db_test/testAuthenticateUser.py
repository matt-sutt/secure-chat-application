import unittest
import tempfile
import os
from socp.modularImp.db import DatabaseManager


class TestAuthenticateUser(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmpdir.name, "test_auth.db")
        self.db = DatabaseManager(db_path=self.db_path)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_register_and_login(self):
        reg = self.db.register_user("alice", "Abcdef12")
        self.assertTrue(reg.get("Register_Status"), f"register failed: {reg}")

        ok = self.db.authenticate_user("alice", "Abcdef12")
        self.assertTrue(ok.get("Login_Status"), f"auth failed: {ok}")

    def test_login_wrong_password(self):
        self.db.register_user("alice", "Abcdef12")
        bad = self.db.authenticate_user("alice", "nopeNOPE1")
        self.assertFalse(bad.get("Login_Status"))
        self.assertIn("invalid username or password", bad.get("error", ""))

    def test_login_unknown_user(self):
        miss = self.db.authenticate_user("ghost", "whatever")
        # your code returns {"Login_Status": False, "error": "..."}
        self.assertFalse(miss.get("Login_Status"))

if __name__ == "__main__":
    unittest.main()