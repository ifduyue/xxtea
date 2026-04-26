import os

import xxtea


KEY = os.urandom(16)
DATA_SMALL = os.urandom(64)
DATA_MEDIUM = os.urandom(1000)
DATA_LARGE = os.urandom(10000)
DATA_HUGE = os.urandom(1024 * 1024 * 2)

ENC_SMALL = xxtea.encrypt(DATA_SMALL, KEY)
ENC_MEDIUM = xxtea.encrypt(DATA_MEDIUM, KEY)
ENC_LARGE = xxtea.encrypt(DATA_LARGE, KEY)
ENC_HUGE = xxtea.encrypt(DATA_HUGE, KEY)

HEXENC_MEDIUM = xxtea.encrypt_hex(DATA_MEDIUM, KEY)
HEXENC_HUGE = xxtea.encrypt_hex(DATA_HUGE, KEY)


def test_encrypt_small(benchmark):
    benchmark(xxtea.encrypt, DATA_SMALL, KEY)


def test_encrypt_medium(benchmark):
    benchmark(xxtea.encrypt, DATA_MEDIUM, KEY)


def test_encrypt_large(benchmark):
    benchmark(xxtea.encrypt, DATA_LARGE, KEY)


def test_decrypt_small(benchmark):
    benchmark(xxtea.decrypt, ENC_SMALL, KEY)


def test_decrypt_medium(benchmark):
    benchmark(xxtea.decrypt, ENC_MEDIUM, KEY)


def test_decrypt_large(benchmark):
    benchmark(xxtea.decrypt, ENC_LARGE, KEY)


def test_encrypt_hex(benchmark):
    benchmark(xxtea.encrypt_hex, DATA_MEDIUM, KEY)


def test_decrypt_hex(benchmark):
    benchmark(xxtea.decrypt_hex, HEXENC_MEDIUM, KEY)


def test_encrypt_huge(benchmark):
    benchmark(xxtea.encrypt, DATA_HUGE, KEY)


def test_decrypt_huge(benchmark):
    benchmark(xxtea.decrypt, ENC_HUGE, KEY)


def test_encrypt_hex_huge(benchmark):
    benchmark(xxtea.encrypt_hex, DATA_HUGE, KEY)


def test_decrypt_hex_huge(benchmark):
    benchmark(xxtea.decrypt_hex, HEXENC_HUGE, KEY)
