import unittest
import tempfile
import os
from socp.modularImp.db import DatabaseManager


class TestPasswordValidation(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmpdir.name, "test_validation.db")
        self.db = DatabaseManager(db_path=self.db_path)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_valid_password(self):
        self.assertTrue(self.db.validate_password("Abcdef12"))

    def test_too_short(self):
        self.assertFalse(self.db.validate_password("Abc1def"))

    def test_missing_uppercase(self):
        self.assertFalse(self.db.validate_password("abcdef12"))

    def test_missing_lowercase(self):
        self.assertFalse(self.db.validate_password("ABCDEF12"))

    def test_missing_digit(self):
        self.assertFalse(self.db.validate_password("Abcdefgh"))
