import json
import os
import pathlib
import unittest
import warnings

import xxtea


VECTORS8 = json.loads(
    (pathlib.Path(__file__).resolve().parent / 'vectors8.json').read_text()
)


class TestPadding8(unittest.TestCase):
    def test_constants(self):
        self.assertIs(xxtea.PKCS7_4_MIN8, xxtea.Padding.PKCS7_4_MIN8)
        self.assertIs(xxtea.PKCS7_8, xxtea.Padding.PKCS7_8)
        self.assertIs(xxtea.XXTEA.PKCS7_4_MIN8, xxtea.Padding.PKCS7_4_MIN8)
        self.assertIs(xxtea.XXTEA.PKCS7_8, xxtea.Padding.PKCS7_8)
        self.assertIs(xxtea.XXTEA.Padding, xxtea.Padding)
        self.assertEqual(xxtea.PKCS7_4_MIN8, 'pkcs7_4_min8')
        self.assertEqual(xxtea.PKCS7_8, 'pkcs7_8')
        self.assertEqual(xxtea.Padding.NONE, 'none')
        self.assertIsInstance(xxtea.PKCS7_8, xxtea.Padding)
        self.assertIsInstance(xxtea.PKCS7_8, str)

    def test_true_equals_pkcs7_4_min8(self):
        key = os.urandom(16)
        data = os.urandom(32)
        self.assertEqual(xxtea.encrypt(data, key, padding=True),
                         xxtea.encrypt(data, key, padding='pkcs7_4_min8'))
        self.assertEqual(xxtea.encrypt(data, key, padding=True),
                         xxtea.encrypt(data, key, padding=xxtea.PKCS7_4_MIN8))
        self.assertEqual(xxtea.encrypt(data, key, padding=True),
                         xxtea.encrypt(data, key, padding=xxtea.Padding.PKCS7_4_MIN8))

    def test_false_equals_none(self):
        key = os.urandom(16)
        data = os.urandom(32)
        self.assertEqual(xxtea.encrypt(data, key, padding=False),
                         xxtea.encrypt(data, key, padding='none'))
        self.assertEqual(xxtea.encrypt(data, key, padding=False),
                         xxtea.encrypt(data, key, padding=xxtea.Padding.NONE))
        self.assertEqual(xxtea.encrypt(data, key, padding=False),
                         xxtea.encrypt(data, key, padding=None))
        cipher = xxtea.XXTEA(key, padding=None)
        self.assertEqual(xxtea.encrypt(data, key, padding=False),
                         cipher.encrypt(data))

    def test_xxteang_vectors(self):
        for i, vec in enumerate(VECTORS8):
            data = bytes.fromhex(vec['data'])
            key = bytes.fromhex(vec['key'])
            expected = bytes.fromhex(vec['enc'])

            enc = xxtea.encrypt(data, key, padding='pkcs7_8')
            self.assertEqual(expected, enc,
                             f'encrypt mismatch at vector {i} len={vec["len"]}')
            self.assertEqual(vec['ct_len'], len(enc))

            dec = xxtea.decrypt(enc, key, padding='pkcs7_8')
            self.assertEqual(data, dec,
                             f'decrypt mismatch at vector {i} len={vec["len"]}')

            hexenc = xxtea.encrypt_hex(data, key, padding='pkcs7_8')
            self.assertEqual(vec['enc'].encode(), hexenc)
            self.assertEqual(data, xxtea.decrypt_hex(hexenc, key, padding='pkcs7_8'))

    def test_8_differs_from_4_for_8_byte_input(self):
        key = b'abcdefghijklmnop'
        data = b'12345678'
        enc4 = xxtea.encrypt(data, key, padding='pkcs7_4_min8')
        enc8 = xxtea.encrypt(data, key, padding='pkcs7_8')
        self.assertNotEqual(enc4, enc8)
        self.assertEqual(12, len(enc4))
        self.assertEqual(16, len(enc8))
        self.assertEqual(data, xxtea.decrypt(enc4, key, padding='pkcs7_4_min8'))
        self.assertEqual(data, xxtea.decrypt(enc8, key, padding='pkcs7_8'))

    def test_8_matches_4_for_short_inputs(self):
        key = os.urandom(16)
        for length in range(8):
            data = os.urandom(length)
            enc4 = xxtea.encrypt(data, key, padding='pkcs7_4_min8')
            enc8 = xxtea.encrypt(data, key, padding='pkcs7_8')
            self.assertEqual(enc4, enc8,
                             f'len={length} should match between pkcs7_4_min8 and pkcs7_8')

    def test_roundtrip_all_lengths(self):
        key = os.urandom(16)
        for length in range(64):
            data = os.urandom(length)
            enc = xxtea.encrypt(data, key, padding='pkcs7_8')
            self.assertEqual(0, len(enc) % 8)
            self.assertGreaterEqual(len(enc), 8)
            self.assertEqual(data, xxtea.decrypt(enc, key, padding='pkcs7_8'),
                             f'length={length}')

    def test_8byte_edge(self):
        key = os.urandom(16)
        for last in range(256):
            data = bytes([0] * 7 + [last])
            enc = xxtea.encrypt(data, key, padding='pkcs7_8')
            self.assertEqual(16, len(enc))
            self.assertEqual(data, xxtea.decrypt(enc, key, padding='pkcs7_8'))

    def test_empty_and_short(self):
        key = os.urandom(16)
        for length in range(8):
            data = os.urandom(length)
            enc = xxtea.encrypt(data, key, padding='pkcs7_8')
            self.assertEqual(8, len(enc))
            self.assertEqual(data, xxtea.decrypt(enc, key, padding='pkcs7_8'))

    def test_cipher_object(self):
        key = os.urandom(16)
        data = os.urandom(32)
        cipher = xxtea.XXTEA(key, padding='pkcs7_8')
        self.assertEqual(xxtea.encrypt(data, key, padding='pkcs7_8'),
                         cipher.encrypt(data))
        self.assertEqual(data, cipher.decrypt(cipher.encrypt(data)))

    def test_cipher_padding_constant(self):
        key = os.urandom(16)
        cipher = xxtea.XXTEA(key, padding=xxtea.PKCS7_8)
        self.assertEqual(b'12345678', cipher.decrypt(cipher.encrypt(b'12345678')))
        cipher = xxtea.XXTEA(key, padding=xxtea.Padding.PKCS7_8)
        self.assertEqual(b'12345678', cipher.decrypt(cipher.encrypt(b'12345678')))
        cipher = xxtea.XXTEA(key, padding=xxtea.XXTEA.PKCS7_8)
        self.assertEqual(b'12345678', cipher.decrypt(cipher.encrypt(b'12345678')))

    def test_invalid_padding_value(self):
        key = b'k' * 16
        data = b'12345678'
        with self.assertRaises(ValueError):
            xxtea.encrypt(data, key, padding='pkcs7')
        with self.assertRaises(ValueError):
            xxtea.encrypt(data, key, padding='pkcs7_4')
        with self.assertRaises(ValueError):
            xxtea.encrypt(data, key, padding='xxtea')
        with self.assertRaises(ValueError):
            xxtea.encrypt(data, key, padding='pkcs7_16')
        with self.assertRaises(ValueError):
            xxtea.XXTEA(key, padding='zero')

    def test_truthiness_compat(self):
        """0/empty still disable padding; 1/8 stay default padding."""
        key = os.urandom(16)
        data = os.urandom(32)
        enc_false = xxtea.encrypt(data, key, padding=False)
        enc_true = xxtea.encrypt(data, key, padding=True)

        def legacy_encrypt(padding):
            with self.assertWarns(DeprecationWarning) as cm:
                enc = xxtea.encrypt(data, key, padding=padding)
            self.assertIn('next major version', str(cm.warning))
            self.assertIn('LENGTH_WORD_SUFFIX', str(cm.warning))
            return enc

        self.assertEqual(enc_false, legacy_encrypt(0))
        self.assertEqual(enc_false, legacy_encrypt([]))
        self.assertEqual(enc_false, legacy_encrypt(''))
        self.assertEqual(enc_true, legacy_encrypt(1))
        self.assertEqual(enc_true, legacy_encrypt(8))
        self.assertEqual(enc_true, legacy_encrypt(16))
        with self.assertWarns(DeprecationWarning):
            dec = xxtea.decrypt(enc_false, key, padding=0)
        self.assertEqual(data, dec)
        with self.assertWarns(DeprecationWarning):
            dec = xxtea.decrypt(enc_true, key, padding=1)
        self.assertEqual(data, dec)
        with self.assertWarns(DeprecationWarning):
            cipher = xxtea.XXTEA(key, padding=0)
        self.assertEqual(enc_false, cipher.encrypt(data))

    def test_value_getter_errors_are_not_swallowed(self):
        key = os.urandom(16)
        data = os.urandom(32)

        class Boom:
            @property
            def value(self):
                raise RuntimeError('boom')

        with self.assertRaises(RuntimeError):
            xxtea.encrypt(data, key, padding=Boom())

        class NoValue:
            pass

        with self.assertWarns(DeprecationWarning):
            enc = xxtea.encrypt(data, key, padding=NoValue())
        self.assertEqual(enc, xxtea.encrypt(data, key, padding=True))

    def test_standard_padding_does_not_warn(self):
        key = os.urandom(16)
        data = os.urandom(32)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always', DeprecationWarning)
            xxtea.encrypt(data, key, padding=True)
            xxtea.encrypt(data, key, padding=None)
            xxtea.encrypt(data, key, padding=False)
            xxtea.encrypt(data, key, padding='pkcs7_4_min8')
            xxtea.encrypt(data, key, padding='pkcs7_8')
            xxtea.encrypt(data, key, padding='none')
            xxtea.encrypt(data, key, padding=xxtea.Padding.PKCS7_4_MIN8)
            xxtea.encrypt(data, key, padding=xxtea.Padding.PKCS7_8)
            xxtea.encrypt(data, key, padding=xxtea.Padding.NONE)
            xxtea.encrypt(data, key, padding=xxtea.LENGTH_WORD_SUFFIX)
            xxtea.XXTEA(key, padding=True)
            xxtea.XXTEA(key, padding=None)
            xxtea.XXTEA(key, padding=xxtea.PKCS7_8)
        self.assertEqual([], [w for w in caught
                              if issubclass(w.category, DeprecationWarning)])

    def test_how_do_you_do_same_as_4byte(self):
        data = b'How do you do?'
        key = b'Fine. And you?  '
        enc4 = xxtea.encrypt(data, key)
        enc8 = xxtea.encrypt(data, key, padding='pkcs7_8')
        self.assertEqual(enc4, enc8)
        self.assertEqual(b'78f465eb1b4985887d11842ede853621',
                         xxtea.encrypt_hex(data, key, padding='pkcs7_8'))

    def test_digits_xxteang_vector(self):
        data = b'0123456789'
        key = b'abcdefghijklmnop'
        self.assertEqual(b'90f829f7271461d1d47efae4f5fde383',
                         xxtea.encrypt_hex(data, key, padding='pkcs7_8'))

    def test_positional_pkcs7_8(self):
        key = os.urandom(16)
        data = os.urandom(32)
        enc_pos = xxtea.encrypt(data, key, 'pkcs7_8')
        enc_kw = xxtea.encrypt(data, key, padding='pkcs7_8')
        self.assertEqual(enc_pos, enc_kw)
        self.assertEqual(data, xxtea.decrypt(enc_pos, key, 'pkcs7_8'))


if __name__ == '__main__':
    unittest.main()
