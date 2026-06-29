import unittest
import xxtea


class TestBigEndianInPlaceLongs2Bytes(unittest.TestCase):
    """
    Regression test for the big-endian in-place longs2bytes bug.

    _decrypt_impl reuses the same PyBytes buffer as both the uint32_t word
    array and the byte output.  On big-endian machines longs2bytes must swap
    each word's bytes in place.  A naive implementation that re-reads in[i]
    after writing s[4*i] corrupts the word, so we exercise decrypt with
    plaintext bytes that span all four byte positions of a 32-bit word.
    """

    def test_decrypt_words_with_distinct_bytes(self):
        key = b'0123456789abcdef'
        # Each 4-byte chunk has distinct bytes so that swapping errors show up.
        data = bytes([
            0x00, 0x11, 0x22, 0x33,  # word 0
            0x44, 0x55, 0x66, 0x77,  # word 1
            0x88, 0x99, 0xaa, 0xbb,  # word 2
            0xcc, 0xdd, 0xee, 0xff,  # word 3
        ])
        enc = xxtea.encrypt(data, key)
        dec = xxtea.decrypt(enc, key)
        self.assertEqual(dec, data)

    def test_decrypt_mixed_lengths(self):
        key = b'0123456789abcdef'
        for length in range(0, 256):
            data = bytes((i * 7 + 13) & 0xff for i in range(length))
            enc = xxtea.encrypt(data, key)
            dec = xxtea.decrypt(enc, key)
            self.assertEqual(dec, data, f'failed for length={length}')


if __name__ == '__main__':
    unittest.main()
