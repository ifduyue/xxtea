import unittest
import random
import xxtea
import os


class TestXXTEA(unittest.TestCase):

    def test_hex(self):
        self.assertEqual(xxtea.encrypt_hex('How do you do?', 'Fine. And you?  '), b'78f465eb1b4985887d11842ede853621')
        self.assertEqual(xxtea.decrypt_hex('78f465eb1b4985887d11842ede853621', 'Fine. And you?  '), b'How do you do?')

    def test_raw(self):
        encd = xxtea.encrypt('How do you do?', 'Fine. And you?  ')
        decd = xxtea.decrypt(encd, 'Fine. And you?  ')
        self.assertEqual(b'How do you do?', decd)

    def test_urandom(self):
        for i in range(100):
            key = os.urandom(16)

            data = os.urandom(i)
            encd = xxtea.encrypt(data, key)
            decd = xxtea.decrypt(encd, key)
            self.assertEqual(data, decd)

            data = b'\0' * i
            encd = xxtea.encrypt(data, key)
            decd = xxtea.decrypt(encd, key)
            self.assertEqual(data, decd)


if __name__ == '__main__':
    unittest.main()
