import unittest
import random
import xxtea


class TestXXTEA(unittest.TestCase):

    def test_encrypt(self):
        self.assertEqual(xxtea.encrypt('How do you do?', 'Fine. And you?'), 'dd2c3bffc7b08b20c2700eb51539c18f')

    def test_decrypt(self):
        self.assertEqual(xxtea.decrypt('dd2c3bffc7b08b20c2700eb51539c18f', 'Fine. And you?'), 'How do you do?')

if __name__ == '__main__':
    unittest.main()
