import os
import binascii

import unittest
import xxtea


class TestXXTEA(unittest.TestCase):

    def test_hex(self):
        data = b'How do you do?'
        key = b'Fine. And you?  '
        hexenc = b'78f465eb1b4985887d11842ede853621'
        self.assertEqual(xxtea.encrypt_hex(data, key), hexenc)
        self.assertEqual(xxtea.decrypt_hex(hexenc, key), data)

    def test_raw(self):
        data = b'How do you do?'
        key = b'Fine. And you?  '
        hexenc = b'78f465eb1b4985887d11842ede853621'
        enc = binascii.a2b_hex(hexenc)

        self.assertEqual(xxtea.encrypt(data, key), enc)
        self.assertEqual(xxtea.decrypt(enc, key), data)

    def test_urandom(self):
        for i in range(2048):
            key = os.urandom(16)
            data = os.urandom(i)

            enc = xxtea.encrypt(data, key)
            dec = xxtea.decrypt(enc, key)
            self.assertEqual(data, dec)

            data = b'\0' * i
            enc = xxtea.encrypt(data, key)
            dec = xxtea.decrypt(enc, key)
            self.assertEqual(data, dec)

    def test_hex_encode(self):
        for i in range(2048):
            key = os.urandom(16)
            data = os.urandom(i)

            enc = xxtea.encrypt(data, key)
            hexenc = xxtea.encrypt_hex(data, key)
            self.assertEqual(binascii.b2a_hex(enc), hexenc)

if __name__ == '__main__':
    unittest.main()
