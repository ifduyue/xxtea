CHANGELOG
--------------

v3.7.0 2025/11/28
~~~~~~~~~~~~~~~~~~~

- Build linux riscv64 wheels
- Build linux armv7l wheels

v3.6.0 2025/11/04
~~~~~~~~~~~~~~~~~~~

- Build Android and iOS wheels
- Build pypy and pypy-eol wheels


v3.5.0 2025/10/02
~~~~~~~~~~~~~~~~~~~

- Support Python Free Threading


v3.4.0 2025/10/01
~~~~~~~~~~~~~~~~~~~

- Build wheels for Python 3.14
- Drop support for Python 3.6


v3.3.0 2024/08/09
~~~~~~~~~~~~~~~~~~~

- Build wheels for Python 3.13


v3.2.0 2023/10/06
~~~~~~~~~~~~~~~~~~~

- Build wheels for Python 3.12
- Remove custom extra_compile_args from setup.py

v3.1.0 2023/07/29
~~~~~~~~~~~~~~~~~~~

- Build windows arm64 wheels

v3.0.0 2023/05/06
~~~~~~~~~~~~~~~~~~~

- Add support for Python 3.11
- Fix Py_SET_SIZE for Python 2.x
- Set up github actions and remove TravisCI and AppVeyor
- Drop support for Python 2.7, 3.4 and 3.5. Now xxtea requires Python >= 3.6

v2.1.0 2023/04/14
~~~~~~~~~~~~~~~~~~~

- Drop support for EOL Python 2.7, 3.4 and 3.5
- Add support for Python 3.9, 1.10 and 3.11

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
