import json
import os
import pathlib
import unittest
import warnings

import xxtea


VECTORS = json.loads(
    (pathlib.Path(__file__).resolve().parent / 'vectors_length_word_prefix.json').read_text()
)


class TestLengthWordPrefix(unittest.TestCase):
    def test_constants(self):
        self.assertIs(xxtea.LENGTH_WORD_PREFIX, xxtea.Padding.LENGTH_WORD_PREFIX)
        self.assertIs(xxtea.XXTEA.LENGTH_WORD_PREFIX, xxtea.Padding.LENGTH_WORD_PREFIX)
        self.assertEqual(xxtea.LENGTH_WORD_PREFIX, 'length_word_prefix')
        self.assertIsInstance(xxtea.LENGTH_WORD_PREFIX, xxtea.Padding)
        self.assertIsInstance(xxtea.LENGTH_WORD_PREFIX, str)
        self.assertNotEqual(xxtea.LENGTH_WORD_PREFIX, xxtea.LENGTH_WORD_SUFFIX)

    def test_known_vectors(self):
        for i, vec in enumerate(VECTORS):
            data = bytes.fromhex(vec['data'])
            key = bytes.fromhex(vec['key'])
            expected = bytes.fromhex(vec['enc'])

            enc = xxtea.encrypt(data, key, padding='length_word_prefix')
            self.assertEqual(expected, enc,
                             f'encrypt mismatch at vector {i} len={vec["len"]}')
            self.assertEqual(vec['ct_len'], len(enc))

            dec = xxtea.decrypt(enc, key, padding='length_word_prefix')
            self.assertEqual(data, dec,
                             f'decrypt mismatch at vector {i} len={vec["len"]}')

            hexenc = xxtea.encrypt_hex(data, key, padding=xxtea.LENGTH_WORD_PREFIX)
            self.assertEqual(vec['enc'].encode(), hexenc)
            self.assertEqual(data, xxtea.decrypt_hex(hexenc, key,
                                                     padding='length_word_prefix'))

    def test_roundtrip_all_lengths(self):
        key = os.urandom(16)
        for length in range(0, 300):
            data = os.urandom(length)
            enc = xxtea.encrypt(data, key, padding=xxtea.LENGTH_WORD_PREFIX)
            self.assertEqual(8 if length == 0 else ((length + 3) // 4) * 4 + 4,
                             len(enc), f'length={length}')
            self.assertEqual(data, xxtea.decrypt(enc, key, padding='length_word_prefix'),
                             f'length={length}')

    def test_length_word_is_little_endian(self):
        """First plaintext word is the original length as little-endian uint32."""
        key = os.urandom(16)
        for length in (0, 1, 2, 3, 4, 5, 127, 128, 255, 256, 257,
                       0x0102, 0x010203):
            data = b'\xAA' * length
            enc = xxtea.encrypt(data, key, padding='length_word_prefix')
            raw = xxtea.decrypt(enc, key, padding=False)
            le = int.from_bytes(raw[:4], 'little')
            be = int.from_bytes(raw[:4], 'big')
            self.assertEqual(length, le, length)
            if le != be:
                self.assertNotEqual(length, be, length)

    def test_empty_is_encrypted(self):
        key = os.urandom(16)
        enc = xxtea.encrypt(b'', key, padding='length_word_prefix')
        self.assertEqual(8, len(enc))
        self.assertNotEqual(b'', enc)
        self.assertEqual(b'', xxtea.decrypt(enc, key, padding='length_word_prefix'))
        with self.assertRaises(ValueError):
            xxtea.decrypt(b'', key, padding='length_word_prefix')
        cipher = xxtea.XXTEA(key, padding=xxtea.LENGTH_WORD_PREFIX)
        self.assertEqual(enc, cipher.encrypt(b''))
        self.assertEqual(b'', cipher.decrypt(enc))
        # Empty input: [len=0][zero] for prefix vs [zero][len=0] for
        # suffix — identical bytes.
        self.assertEqual(enc, xxtea.encrypt(b'', key, padding='length_word_suffix'))

    def test_differs_from_suffix_when_nonempty(self):
        key = os.urandom(16)
        data = b'hello'
        self.assertNotEqual(
            xxtea.encrypt(data, key, padding='length_word_prefix'),
            xxtea.encrypt(data, key, padding='length_word_suffix'))

    def test_leftover_bytes_must_be_zero(self):
        key = os.urandom(16)
        # length 1, then 1 data byte + 3 nonzero pad bytes.
        raw = bytes([1, 0, 0, 0, 0xAA, 0x01, 0x01, 0x01])
        enc = xxtea.encrypt(raw, key, padding=False)
        with self.assertRaises(ValueError):
            xxtea.decrypt(enc, key, padding='length_word_prefix')
        raw_ok = bytes([1, 0, 0, 0, 0xAA, 0, 0, 0])
        enc_ok = xxtea.encrypt(raw_ok, key, padding=False)
        self.assertEqual(b'\xAA', xxtea.decrypt(enc_ok, key, padding='length_word_prefix'))

    def test_empty_extra_word_must_be_zero(self):
        key = os.urandom(16)
        raw = bytes([0, 0, 0, 0, 1, 0, 0, 0])
        enc = xxtea.encrypt(raw, key, padding=False)
        with self.assertRaises(ValueError):
            xxtea.decrypt(enc, key, padding='length_word_prefix')
        raw_ok = bytes(8)
        enc_ok = xxtea.encrypt(raw_ok, key, padding=False)
        self.assertEqual(b'', xxtea.decrypt(enc_ok, key, padding='length_word_prefix'))
        self.assertEqual(enc_ok, xxtea.encrypt(b'', key, padding='length_word_prefix'))

    def test_invalid_length_word(self):
        key = os.urandom(16)
        enc = bytearray(xxtea.encrypt(b'A' * 16, key, padding='length_word_prefix'))
        for pos in (0, 1, 2, 3):
            bad = bytearray(enc)
            bad[pos] ^= 0xFF
            with self.assertRaises(ValueError):
                xxtea.decrypt(bytes(bad), key, padding='length_word_prefix')

    def test_decrypt_rejects_short_and_uneven(self):
        key = os.urandom(16)
        for bad in (b'', b'\x00' * 4, b'\x00' * 5, b'\x00' * 6):
            with self.assertRaises(ValueError):
                xxtea.decrypt(bad, key, padding='length_word_prefix')

    def test_positional_padding(self):
        key = os.urandom(16)
        data = os.urandom(64)
        self.assertEqual(xxtea.encrypt(data, key, padding='length_word_prefix'),
                         xxtea.encrypt(data, key, 'length_word_prefix'))
        self.assertEqual(data, xxtea.decrypt(
            xxtea.encrypt(data, key, 'length_word_prefix'), key, 'length_word_prefix'))

    def test_cipher_object(self):
        key = os.urandom(16)
        data = os.urandom(100)
        cipher = xxtea.XXTEA(key, padding=xxtea.LENGTH_WORD_PREFIX)
        enc = cipher.encrypt(data)
        self.assertEqual(((100 + 3) // 4) * 4 + 4, len(enc))
        self.assertEqual(data, cipher.decrypt(enc))
        cipher_str = xxtea.XXTEA(key, padding='length_word_prefix')
        self.assertEqual(cipher.encrypt(data), cipher_str.encrypt(data))
        self.assertEqual(data, cipher_str.decrypt(cipher.encrypt(data)))

    def test_no_deprecation_warning(self):
        key = os.urandom(16)
        data = os.urandom(32)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always', DeprecationWarning)
            xxtea.encrypt(data, key, padding='length_word_prefix')
            xxtea.encrypt(data, key, padding=xxtea.LENGTH_WORD_PREFIX)
            xxtea.XXTEA(key, padding=xxtea.LENGTH_WORD_PREFIX)
        self.assertEqual([], [w for w in caught
                              if issubclass(w.category, DeprecationWarning)])

    def test_unknown_close_names_rejected(self):
        key = b'k' * 16
        data = b'12345678'
        for name in ('length_word', 'LENGTH_WORD_PREFIX', 'length-word-prefix',
                     'length_prefix'):
            with self.assertRaises(ValueError):
                xxtea.encrypt(data, key, padding=name)


if __name__ == '__main__':
    unittest.main()
