import unittest
from socp.modularImp.our_crytography import Cryptography


class TestCryptography(unittest.TestCase):
    def setUp(self):
        self.cryp = Cryptography()
        self.priv, self.pub = self.cryp.generate_rsa_keys()

    def test_rsa_oaep_roundtrip(self):
        msg = "Hello, this is a test message!"
        ct_b64 = self.cryp.encrypt_rsa_oaep_b64(self.pub, msg.encode("utf-8"))
        pt = self.cryp.decrypt_rsa_oaep_b64(self.priv, ct_b64).decode("utf-8")
        self.assertEqual(pt, msg)

    def test_pss_sign_verify(self):
        data = b"sign this"
        sig_b64 = self.cryp.sign_pss_b64(self.priv, data)
        self.assertTrue(self.cryp.verify_pss_b64(self.pub, data, sig_b64))
        # Tampered data should fail
        self.assertFalse(self.cryp.verify_pss_b64(self.pub, b"sign this!", sig_b64))


if __name__ == "__main__":
    unittest.main()
