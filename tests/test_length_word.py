import gzip
import json
import os
import pathlib
import unittest
import warnings

import xxtea


VECTORS = json.loads(
    (pathlib.Path(__file__).resolve().parent / 'vectors_length_word.json').read_text()
)

# A real Cocos Creator build encrypts gzip(js): js -> gzip -> XXTEA.
_JS = b'window.__require = function e(t, i, a) { return 42; }'
_COCOS_KEY = b'eba10b03-5d74-49'


def _gzip_js(js):
    # mtime=0: gzip.compress default mtime is "now" at 1s resolution, so
    # two calls that straddle a second would make the pipeline test flake.
    return gzip.compress(js, mtime=0)


def _cocos_jsc(js, key):
    """Build a .jsc the way Cocos Creator does (gzip + XXTEA)."""
    return xxtea.encrypt(_gzip_js(js), key, padding='length_word_suffix')


class TestLengthWordSuffix(unittest.TestCase):
    def test_constants(self):
        self.assertIs(xxtea.LENGTH_WORD_SUFFIX, xxtea.Padding.LENGTH_WORD_SUFFIX)
        self.assertIs(xxtea.XXTEA.PKCS7_8, xxtea.Padding.PKCS7_8)
        self.assertIs(xxtea.XXTEA.LENGTH_WORD_SUFFIX, xxtea.Padding.LENGTH_WORD_SUFFIX)
        self.assertEqual(xxtea.LENGTH_WORD_SUFFIX, 'length_word_suffix')
        self.assertIsInstance(xxtea.LENGTH_WORD_SUFFIX, xxtea.Padding)
        self.assertIsInstance(xxtea.LENGTH_WORD_SUFFIX, str)

    def test_known_vectors(self):
        """Byte-exact against stored ciphertexts of the Cocos JSC layout."""
        for i, vec in enumerate(VECTORS):
            data = bytes.fromhex(vec['data'])
            key = bytes.fromhex(vec['key'])
            expected = bytes.fromhex(vec['enc'])

            enc = xxtea.encrypt(data, key, padding='length_word_suffix')
            self.assertEqual(expected, enc,
                             f'encrypt mismatch at vector {i} len={vec["len"]}')
            self.assertEqual(vec['ct_len'], len(enc))

            dec = xxtea.decrypt(enc, key, padding='length_word_suffix')
            self.assertEqual(data, dec,
                             f'decrypt mismatch at vector {i} len={vec["len"]}')

            hexenc = xxtea.encrypt_hex(data, key, padding=xxtea.LENGTH_WORD_SUFFIX)
            self.assertEqual(vec['enc'].encode(), hexenc)
            self.assertEqual(data, xxtea.decrypt_hex(hexenc, key, padding='length_word_suffix'))

    def test_roundtrip_all_lengths(self):
        key = os.urandom(16)
        for length in range(0, 300):
            data = os.urandom(length)
            enc = xxtea.encrypt(data, key, padding=xxtea.LENGTH_WORD_SUFFIX)
            self.assertEqual(8 if length == 0 else ((length + 3) // 4) * 4 + 4,
                             len(enc), f'length={length}')
            self.assertEqual(data, xxtea.decrypt(enc, key, padding='length_word_suffix'),
                             f'length={length}')

    def test_length_word_is_little_endian(self):
        """Last plaintext word is the original length as little-endian uint32."""
        key = os.urandom(16)
        for length in (0, 1, 2, 3, 4, 5, 127, 128, 255, 256, 257,
                       0x0102, 0x010203):
            data = b'\xAA' * length
            enc = xxtea.encrypt(data, key, padding='length_word_suffix')
            raw = xxtea.decrypt(enc, key, padding=False)
            le = int.from_bytes(raw[-4:], 'little')
            be = int.from_bytes(raw[-4:], 'big')
            self.assertEqual(length, le, length)
            if le != be:
                self.assertNotEqual(length, be, length)

    def test_empty_is_encrypted(self):
        key = os.urandom(16)
        enc = xxtea.encrypt(b'', key, padding='length_word_suffix')
        self.assertEqual(8, len(enc))
        self.assertNotEqual(b'', enc)
        self.assertEqual(b'', xxtea.decrypt(enc, key, padding='length_word_suffix'))
        with self.assertRaises(ValueError):
            xxtea.decrypt(b'', key, padding='length_word_suffix')
        cipher = xxtea.XXTEA(key, padding=xxtea.LENGTH_WORD_SUFFIX)
        self.assertEqual(enc, cipher.encrypt(b''))
        self.assertEqual(b'', cipher.decrypt(enc))

    def test_cocos_pipeline(self):
        """gzip(js) encrypted like Creator must decrypt and gunzip back."""
        gz = _gzip_js(_JS)
        jsc = _cocos_jsc(_JS, _COCOS_KEY)
        plaintext = xxtea.decrypt(jsc, _COCOS_KEY, padding='length_word_suffix')
        self.assertEqual(gz, plaintext)
        self.assertEqual(_JS, gzip.decompress(plaintext))

    def test_cocos_pipeline_deterministic(self):
        jsc1 = _cocos_jsc(_JS, _COCOS_KEY)
        jsc2 = _cocos_jsc(_JS, _COCOS_KEY)
        self.assertEqual(jsc1, jsc2)

    def test_leftover_bytes_must_be_zero(self):
        key = os.urandom(16)
        # 1 data byte + 3 nonzero pad bytes + length 1, no extra padding.
        raw = bytes([0xAA, 0x01, 0x01, 0x01, 1, 0, 0, 0])
        enc = xxtea.encrypt(raw, key, padding=False)
        with self.assertRaises(ValueError):
            xxtea.decrypt(enc, key, padding='length_word_suffix')
        raw_ok = bytes([0xAA, 0, 0, 0, 1, 0, 0, 0])
        enc_ok = xxtea.encrypt(raw_ok, key, padding=False)
        self.assertEqual(b'\xAA', xxtea.decrypt(enc_ok, key, padding='length_word_suffix'))

    def test_empty_extra_word_must_be_zero(self):
        key = os.urandom(16)
        raw = bytes([1, 0, 0, 0, 0, 0, 0, 0])
        enc = xxtea.encrypt(raw, key, padding=False)
        with self.assertRaises(ValueError):
            xxtea.decrypt(enc, key, padding='length_word_suffix')
        raw_ok = bytes(8)
        enc_ok = xxtea.encrypt(raw_ok, key, padding=False)
        self.assertEqual(b'', xxtea.decrypt(enc_ok, key, padding='length_word_suffix'))
        self.assertEqual(enc_ok, xxtea.encrypt(b'', key, padding='length_word_suffix'))

    def test_invalid_length_word(self):
        key = os.urandom(16)
        enc = bytearray(xxtea.encrypt(b'A' * 16, key, padding='length_word_suffix'))
        # Corrupt the trailing length word: no valid length can remain.
        for pos in (-1, -2, -3, -4):
            bad = bytearray(enc)
            bad[pos] ^= 0xFF
            with self.assertRaises(ValueError):
                xxtea.decrypt(bytes(bad), key, padding='length_word_suffix')

    def test_decrypt_rejects_short_and_uneven(self):
        key = os.urandom(16)
        for bad in (b'', b'\x00' * 4, b'\x00' * 5, b'\x00' * 6):
            with self.assertRaises(ValueError):
                xxtea.decrypt(bad, key, padding='length_word_suffix')

    def test_positional_padding(self):
        key = os.urandom(16)
        data = os.urandom(64)
        self.assertEqual(xxtea.encrypt(data, key, padding='length_word_suffix'),
                         xxtea.encrypt(data, key, 'length_word_suffix'))
        self.assertEqual(data, xxtea.decrypt(
            xxtea.encrypt(data, key, 'length_word_suffix'), key, 'length_word_suffix'))

    def test_cipher_object(self):
        key = os.urandom(16)
        data = os.urandom(100)
        cipher = xxtea.XXTEA(key, padding=xxtea.LENGTH_WORD_SUFFIX)
        enc = cipher.encrypt(data)
        self.assertEqual(((100 + 3) // 4) * 4 + 4, len(enc))
        self.assertEqual(data, cipher.decrypt(enc))
        cipher_none = xxtea.XXTEA(key, padding='length_word_suffix')
        self.assertEqual(cipher.encrypt(data), cipher_none.encrypt(data))
        self.assertEqual(data, cipher_none.decrypt(cipher.encrypt(data)))

    def test_no_deprecation_warning(self):
        key = os.urandom(16)
        data = os.urandom(32)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always', DeprecationWarning)
            xxtea.encrypt(data, key, padding='length_word_suffix')
            xxtea.encrypt(data, key, padding=xxtea.LENGTH_WORD_SUFFIX)
            xxtea.XXTEA(key, padding=xxtea.LENGTH_WORD_SUFFIX)
        self.assertEqual([], [w for w in caught
                              if issubclass(w.category, DeprecationWarning)])

    def test_unknown_close_names_rejected(self):
        key = b'k' * 16
        data = b'12345678'
        for name in ('length_word', 'LENGTH_WORD_SUFFIX', 'length-word-suffix',
                     'length_word_prefix'):
            with self.assertRaises(ValueError):
                xxtea.encrypt(data, key, padding=name)


if __name__ == '__main__':
    unittest.main()
