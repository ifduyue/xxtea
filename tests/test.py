import os
import binascii

import unittest
import xxtea


class TestXXTEA(unittest.TestCase):
    data = b'How do you do?'
    key = b'Fine. And you?  '
    enc = b'x\xf4e\xeb\x1bI\x85\x88}\x11\x84.\xde\x856!'
    hexenc = b'78f465eb1b4985887d11842ede853621'

    def test_version(self):
        version = xxtea.VERSION
        self.assertEqual(True, isinstance(version, str))

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

    def test_zero_bytes(self):
        for i in range(2048):
            data = b'\0' * i


            key = os.urandom(16)
            enc = xxtea.encrypt(data, key)
            dec = xxtea.decrypt(enc, key)
            self.assertEqual(data, dec)

            key = b'\0' * 16
            enc = xxtea.encrypt(data, key)
            dec = xxtea.decrypt(enc, key)
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

        def f3():
            for i in range(1024):
                key = os.urandom(16)
                data = os.urandom(i * 8)

                xxtea.decrypt(data, key=key, padding=False)

        self.assertRaises(ValueError, f1)
        self.assertRaises(ValueError, f2)
        self.assertRaises(ValueError, f3)


class TestArgPassing(unittest.TestCase):
    """Test all parameter passing combinations for encrypt/decrypt/encrypt_hex/decrypt_hex."""

    @classmethod
    def setUpClass(cls):
        cls.key = os.urandom(16)
        cls.data = os.urandom(32)
        cls.enc = xxtea.encrypt(cls.data, cls.key)
        cls.hexenc = xxtea.encrypt_hex(cls.data, cls.key)

    # ── helpers ──────────────────────────────────────────────────────────

    def _try_encrypt(self, *args, **kwargs):
        """Call encrypt and verify by decrypting with the same key+rounds."""
        rounds = kwargs.get('rounds', 0)
        enc = xxtea.encrypt(*args, **kwargs)
        dec = xxtea.decrypt(enc, self.key, rounds=rounds)
        self.assertEqual(dec, self.data)
        return enc

    def _try_decrypt(self, *args, **kwargs):
        """Call decrypt and verify result.
        Re-encrypts self.data with the same parameters first so rounds match."""
        rounds = kwargs.get('rounds', 0)
        padding = kwargs.get('padding', True)
        enc = xxtea.encrypt(self.data, self.key, padding=padding, rounds=rounds)
        dec = xxtea.decrypt(enc, *args[1:], **{k: v for k, v in kwargs.items() if k != 'data'})
        self.assertEqual(dec, self.data)

    def _try_encrypt_hex(self, *args, **kwargs):
        """Call encrypt_hex and verify by decrypting with the same key+rounds."""
        rounds = kwargs.get('rounds', 0)
        hexenc = xxtea.encrypt_hex(*args, **kwargs)
        dec = xxtea.decrypt_hex(hexenc, self.key, rounds=rounds)
        self.assertEqual(dec, self.data)

    def _try_decrypt_hex(self, *args, **kwargs):
        """Call decrypt_hex and verify result.
        Re-encrypts self.data with the same parameters first so rounds match."""
        rounds = kwargs.get('rounds', 0)
        padding = kwargs.get('padding', True)
        hexenc = xxtea.encrypt_hex(self.data, self.key, padding=padding, rounds=rounds)
        dec = xxtea.decrypt_hex(hexenc, *args[1:], **{k: v for k, v in kwargs.items() if k != 'data'})
        self.assertEqual(dec, self.data)

    # ── encrypt ──────────────────────────────────────────────────────────

    def test_encrypt_both_positional(self):
        self._try_encrypt(self.data, self.key)

    def test_encrypt_data_positional_key_keyword(self):
        self._try_encrypt(self.data, key=self.key)

    def test_encrypt_both_keyword(self):
        self._try_encrypt(data=self.data, key=self.key)

    def test_encrypt_both_keyword_swapped(self):
        self._try_encrypt(key=self.key, data=self.data)

    def test_encrypt_all_positional_with_padding(self):
        self._try_encrypt(self.data, self.key, True)

    def test_encrypt_all_positional_with_padding_and_rounds(self):
        self._try_encrypt(self.data, self.key, True, 32)

    def test_encrypt_padding_keyword(self):
        self._try_encrypt(self.data, self.key, padding=True)

    def test_encrypt_rounds_keyword(self):
        self._try_encrypt(self.data, self.key, rounds=32)

    def test_encrypt_both_optional_keyword(self):
        self._try_encrypt(self.data, self.key, padding=True, rounds=32)

    def test_encrypt_nopadding_keyword(self):
        enc = xxtea.encrypt(self.data, self.key, padding=False)
        dec = xxtea.decrypt(enc, self.key, padding=False)
        self.assertEqual(dec, self.data)

    def test_encrypt_all_keyword(self):
        self._try_encrypt(data=self.data, key=self.key, padding=True, rounds=32)

    def test_encrypt_mixed_order(self):
        self._try_encrypt(key=self.key, padding=True, data=self.data)
        self._try_encrypt(rounds=32, key=self.key, data=self.data)

    # ── decrypt ──────────────────────────────────────────────────────────

    def test_decrypt_both_positional(self):
        self._try_decrypt(self.enc, self.key)

    def test_decrypt_data_positional_key_keyword(self):
        self._try_decrypt(self.enc, key=self.key)

    def test_decrypt_both_keyword(self):
        self._try_decrypt(data=self.enc, key=self.key)

    def test_decrypt_both_keyword_swapped(self):
        self._try_decrypt(key=self.key, data=self.enc)

    def test_decrypt_all_positional_with_padding(self):
        self._try_decrypt(self.enc, self.key, True)

    def test_decrypt_all_positional_with_padding_and_rounds(self):
        self._try_decrypt(self.enc, self.key, True, 32)

    def test_decrypt_padding_keyword(self):
        self._try_decrypt(self.enc, self.key, padding=True)

    def test_decrypt_rounds_keyword(self):
        self._try_decrypt(self.enc, self.key, rounds=32)

    def test_decrypt_both_optional_keyword(self):
        self._try_decrypt(self.enc, self.key, padding=True, rounds=32)

    def test_decrypt_nopadding_keyword(self):
        data_nopad = os.urandom(32)
        enc = xxtea.encrypt(data_nopad, self.key, padding=False)
        dec = xxtea.decrypt(enc, self.key, padding=False)
        self.assertEqual(dec, data_nopad)

    def test_decrypt_all_keyword(self):
        self._try_decrypt(data=self.enc, key=self.key, padding=True, rounds=32)

    def test_decrypt_mixed_order(self):
        self._try_decrypt(rounds=32, key=self.key, data=self.enc)

    # ── encrypt_hex ──────────────────────────────────────────────────────

    def test_encrypt_hex_both_positional(self):
        self._try_encrypt_hex(self.data, self.key)

    def test_encrypt_hex_key_keyword(self):
        self._try_encrypt_hex(self.data, key=self.key)

    def test_encrypt_hex_both_keyword(self):
        self._try_encrypt_hex(data=self.data, key=self.key)

    def test_encrypt_hex_both_keyword_swapped(self):
        self._try_encrypt_hex(key=self.key, data=self.data)

    def test_encrypt_hex_padding_keyword(self):
        self._try_encrypt_hex(self.data, self.key, padding=True)

    def test_encrypt_hex_rounds_keyword(self):
        self._try_encrypt_hex(self.data, self.key, rounds=32)

    def test_encrypt_hex_nopadding(self):
        enc = xxtea.encrypt_hex(self.data, self.key, padding=False)
        dec = xxtea.decrypt_hex(enc, self.key, padding=False)
        self.assertEqual(dec, self.data)

    def test_encrypt_hex_all_keyword(self):
        self._try_encrypt_hex(data=self.data, key=self.key, padding=True, rounds=32)

    def test_encrypt_hex_mixed_order(self):
        self._try_encrypt_hex(key=self.key, rounds=32, data=self.data)

    # ── decrypt_hex ──────────────────────────────────────────────────────

    def test_decrypt_hex_both_positional(self):
        self._try_decrypt_hex(self.hexenc, self.key)

    def test_decrypt_hex_key_keyword(self):
        self._try_decrypt_hex(self.hexenc, key=self.key)

    def test_decrypt_hex_both_keyword(self):
        self._try_decrypt_hex(data=self.hexenc, key=self.key)

    def test_decrypt_hex_both_keyword_swapped(self):
        self._try_decrypt_hex(key=self.key, data=self.hexenc)

    def test_decrypt_hex_padding_keyword(self):
        self._try_decrypt_hex(self.hexenc, self.key, padding=True)

    def test_decrypt_hex_rounds_keyword(self):
        self._try_decrypt_hex(self.hexenc, self.key, rounds=32)

    def test_decrypt_hex_nopadding(self):
        data_nopad = os.urandom(32)
        enc = xxtea.encrypt_hex(data_nopad, self.key, padding=False)
        dec = xxtea.decrypt_hex(enc, self.key, padding=False)
        self.assertEqual(dec, data_nopad)

    def test_decrypt_hex_all_keyword(self):
        self._try_decrypt_hex(data=self.hexenc, key=self.key, padding=True, rounds=32)

    def test_decrypt_hex_mixed_order(self):
        self._try_decrypt_hex(rounds=0, key=self.key, data=self.hexenc)

    # ── error cases ──────────────────────────────────────────────────────

    def test_missing_required_arg(self):
        with self.assertRaises(TypeError):
            xxtea.encrypt(self.data)
        with self.assertRaises(TypeError):
            xxtea.encrypt(key=self.key)
        with self.assertRaises(TypeError):
            xxtea.decrypt(self.enc)
        with self.assertRaises(TypeError):
            xxtea.encrypt_hex(self.data)
        with self.assertRaises(TypeError):
            xxtea.decrypt_hex(self.hexenc)

    def test_unknown_keyword(self):
        with self.assertRaises(TypeError):
            xxtea.encrypt(self.data, self.key, bogus=1)
        with self.assertRaises(TypeError):
            xxtea.decrypt(self.enc, self.key, bogus=1)
        with self.assertRaises(TypeError):
            xxtea.encrypt_hex(self.data, self.key, bogus=1)
        with self.assertRaises(TypeError):
            xxtea.decrypt_hex(self.hexenc, self.key, bogus=1)

    def test_duplicate_argument(self):
        with self.assertRaises(TypeError):
            xxtea.encrypt(self.data, self.key, data=self.data)
        with self.assertRaises(TypeError):
            xxtea.decrypt(self.enc, self.key, data=self.enc)

    def test_invalid_rounds_type(self):
        with self.assertRaises(TypeError):
            xxtea.encrypt(self.data, self.key, rounds='not-an-int')
        with self.assertRaises(TypeError):
            xxtea.decrypt(self.enc, self.key, rounds=1.5)


if __name__ == '__main__':
    unittest.main()
