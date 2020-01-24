CHANGELOG
--------------

v2.0.0 2020/01/24
~~~~~~~~~~~~~~~~~~~

- Drop support for EOL Python 2.6, 3.2 and 3.3
- Fix DeprecationWarning: PY_SSIZE_T_CLEAN will be required for '#'

v1.3.0 2018/10/24
~~~~~~~~~~~~~~~~~~~

- Fixed a memory leak in decrypt_hex
- Deployed wheels automatically
- Support specifying rounds

v1.2.0 2018/05/09
~~~~~~~~~~~~~~~~~~~

- Added an option to disable  padding

v1.1.0 2018/02/03
~~~~~~~~~~~~~~~~~~~

- Test on appveyor
- Use ``unsigned int`` instead of ``uint32_t``

v1.0.2 2015/12/15
~~~~~~~~~~~~~~~~~~~

- Check padding char

v1.0.1 2015/12/10
~~~~~~~~~~~~~~~~~~~

- Check upper bound in longs2bytes

v1.0   2015/12/10
~~~~~~~~~~~~~~~~~~~

- Fixed: unbound write
- Changed: raises ValueError instead of TypeError

v0.2.1 2015/03/07
~~~~~~~~~~~~~~~~~~~~

- Fixed: memory leaks
- Use binascii module to encode/decode hex, instead of writing our own C functions.

v0.2.0 2015/02/28
~~~~~~~~~~~~~~~~~~~~

This release is _NOT_ compatible with previous versions.

- [NEW] Added PKCS#7 Padding.
- [NEW] Added `encrypt_hex()` and `decrypt_hex()`.
- [CHANGE] Removed `xxtea.RESULT_TYPE_HEX`, `xxtea.RESULT_TYPE_RAW`, and
  `xxtea.RESULT_TYPE_DEFAULT`. `encrypt()` and `decrypt()` now only
  accept two parameters: input data and key.

v0.1.5 2011/01/23
~~~~~~~~~~~~~~~~~~~~

- fix msvc compiler error
