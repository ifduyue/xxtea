import os
import binascii

import unittest
import xxtea


class TestXXTEA(unittest.TestCase):
    data = b'How do you do?'
    key = b'Fine. And you?  '
    enc = b'x\xf4e\xeb\x1bI\x85\x88}\x11\x84.\xde\x856!'
    hexenc = b'78f465eb1b4985887d11842ede853621'

    def test_encrypt(self):
        enc = xxtea.encrypt(self.data, self.key)
        self.assertEqual(enc, self.enc)

    def test_encrypt_hex(self):
        hexenc = xxtea.encrypt_hex(self.data, self.key)
        self.assertEqual(hexenc, self.hexenc)

    def test_decrypt(self):
        data = xxtea.decrypt(self.enc, self.key)
        self.assertEqual(data, self.data)

    def test_decrypt_hex(self):
        data = xxtea.decrypt_hex(self.hexenc, self.key)
        self.assertEqual(data, self.data)

    def test_urandom(self):
        for i in range(2048):
            key = os.urandom(16)
            data = os.urandom(i)

            enc = xxtea.encrypt(data, key)
            dec = xxtea.decrypt(enc, key)
            self.assertEqual(data, dec)

            for padding in (True, False):
                enc = xxtea.encrypt(data, key, padding)
                dec = xxtea.decrypt(enc, key, padding)
                self.assertEqual(data, dec, padding)

    def test_zero_bytes(self):
        for i in range(2048):
            data = b'\0' * i


            key = os.urandom(16)
            for padding in (True, False):
                enc = xxtea.encrypt(data, key, padding)
                dec = xxtea.decrypt(enc, key, padding)
                self.assertEqual(data, dec)

            key = b'\0' * 16
            for padding in (True, False):
                enc = xxtea.encrypt(data, key, padding)
                dec = xxtea.decrypt(enc, key, padding)
                self.assertEqual(data, dec)

    def test_encrypt_nopadding(self):
        key = os.urandom(16)
        for i in (8, 12, 16, 20):
            data = os.urandom(i)
            enc = xxtea.encrypt(data, key, padding=False)
            dec = xxtea.decrypt(enc, key, padding=False)
            self.assertEqual(data, dec)

    def test_encrypt_hex_nopadding(self):
        key = os.urandom(16)
        for i in (8, 12, 16, 20):
            data = os.urandom(i)
            enc = xxtea.encrypt_hex(data, key, padding=False)
            dec = xxtea.decrypt_hex(enc, key, padding=False)
            self.assertEqual(data, dec)

    def test_encrypt_nopadding_zero(self):
        key = os.urandom(16)
        for i in (8, 12, 16, 20):
            data = b'\0' * i
            enc = xxtea.encrypt(data, key, padding=False)
            dec = xxtea.decrypt(enc, key, padding=False)
            self.assertEqual(data, dec)

    def test_encrypt_hex_nopadding_zero(self):
        key = os.urandom(16)
        for i in (8, 12, 16, 20):
            data = b'\0' * i
            enc = xxtea.encrypt_hex(data, key, padding=False)
            dec = xxtea.decrypt_hex(enc, key, padding=False)
            self.assertEqual(data, dec)

    def test_hex_encode(self):
        for i in range(2048):
            key = os.urandom(16)
            data = os.urandom(i)

            enc = xxtea.encrypt(data, key)
            hexenc = xxtea.encrypt_hex(data, key)
            self.assertEqual(binascii.b2a_hex(enc), hexenc)

    def test_decrypt_invalid(self):
        def f1():
            for i in range(1024):
                key = os.urandom(16)
                data = os.urandom(i * 8)

                xxtea.decrypt(data, key=key)

        def f2():
            for i in range(1024):
                key = os.urandom(16)
                data = os.urandom(i * 8)

                xxtea.decrypt(data, key=key, padding=True)

        def f1():
            for i in range(1024):
                key = os.urandom(16)
                data = os.urandom(i * 8)

                xxtea.decrypt(data, key=key, padding=False)

        self.assertRaises(ValueError, f1)
        self.assertRaises(ValueError, f2)
        self.assertRaises(ValueError, f3)


if __name__ == '__main__':
    unittest.main()
