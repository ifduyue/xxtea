#!/bin/bash

PYTHON=${PYTHON-`which python`}

echo Benchmarking ...

echo -n "    encrypt: "
$PYTHON -mtimeit -s 'import xxtea' -s 'import os' -s 'key = os.urandom(16)' -s 'data = os.urandom(1000)' 'xxtea.encrypt(data, key)'

echo -n "    decrypt: "
$PYTHON -mtimeit -s 'import xxtea' -s 'import os' -s 'key = os.urandom(16)' -s 'data = xxtea.encrypt(os.urandom(1000), key)' 'xxtea.decrypt(data, key)'

echo -n "encrypt_hex: "
$PYTHON -mtimeit -s 'import xxtea' -s 'import os' -s 'key = os.urandom(16)' -s 'data = os.urandom(1000)' 'xxtea.encrypt_hex(data, key)'

echo -n "decrypt_hex: "
$PYTHON -mtimeit -s 'import xxtea' -s 'import os' -s 'key = os.urandom(16)' -s 'data = xxtea.encrypt_hex(os.urandom(1000), key)' 'xxtea.decrypt_hex(data, key)'
