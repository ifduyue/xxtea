xxtea |github-actions-badge| |pypi-badge| |supported-pythons-badge| |license-badge| |codspeed-badge|
=============================================================================================================

.. |github-actions-badge| image:: https://github.com/ifduyue/xxtea/actions/workflows/test.yml/badge.svg
    :target: https://github.com/ifduyue/xxtea/actions/workflows/test.yml
    :alt: Github Actions Status

.. |pypi-badge| image:: https://img.shields.io/pypi/v/xxtea.svg
   :target: https://pypi.python.org/pypi/xxtea
   :alt: Latest Version

.. |supported-pythons-badge| image:: https://img.shields.io/pypi/pyversions/xxtea.svg
    :target: https://pypi.python.org/pypi/xxtea
    :alt: Supported Python versions

.. |license-badge| image:: https://img.shields.io/pypi/l/xxtea.svg
    :target: https://pypi.python.org/pypi/xxtea
    :alt: License

.. |codspeed-badge| image:: https://img.shields.io/endpoint?url=https://codspeed.io/badge.json
    :target: https://codspeed.io/ifduyue/xxtea?utm_source=badge
    :alt: CodSpeed

.. _XXTEA: http://en.wikipedia.org/wiki/XXTEA
.. _longs2bytes: https://github.com/ifduyue/xxtea/blob/master/xxtea.c#L160
.. _bytes2longs: https://github.com/ifduyue/xxtea/blob/master/xxtea.c#L91
.. _PKCS#7: http://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7

XXTEA_ implemented as a Python extension module, licensed under 2-clause BSD.

The XXTEA_ algorithm takes a 128-bit key and operates on an array of 32-bit
integers (at least 2 integers), but it doesn't define the conversions between
bytes and array. Due to this reason, many XXTEA implementations out there are
not compatible with each other.

In this implementation,  the conversions between bytes and array are
taken care of by longs2bytes_ and bytes2longs_. A non-standard 4-byte block
`PKCS#7`_ padding is used by default to make sure that the input bytes are
padded to a multiple of 4-byte (the size of a 32-bit integer) and at least
8-byte long (the size of two 32-bit integers, which is required by the
XXTEA_ algorithm). As a result of these measures, you can encrypt not only
texts, but also any binary bytes of any length.

.. note::

   The default (``"pkcs7_4_min8"``) is **not** standard 4-byte PKCS#7.
   For inputs shorter than 4 bytes it pads an extra 4 bytes (pad values
   5–8) to satisfy XXTEA's 2-word minimum. Pass ``padding="pkcs7_8"`` for
   standard 8-byte PKCS#7 (compatible with Python xxteang), or
   ``padding=False`` for raw XXTEA (requires data length ≥ 8 and
   multiple of 4).


Installation
-------------

::

    $ pip install xxtea -U


Usage
-----------

This module provides four functions: ``encrypt()``, ``decrypt()``,
``encrypt_hex()``, and ``decrypt_hex()``, plus an ``XXTEA`` type for
reusable cipher objects.

.. code-block:: Python

    >>> import os
    >>> import xxtea
    >>> import binascii
    >>>
    >>> key = os.urandom(16)  # Key must be a 16-byte string.
    >>> s = b"xxtea is good"
    >>>
    >>> enc = xxtea.encrypt(s, key)
    >>> dec = xxtea.decrypt(enc, key)
    >>> s == dec
    True
    >>>
    >>> hexenc = xxtea.encrypt_hex(s, key)
    >>> s == xxtea.decrypt_hex(hexenc, key)
    True
    >>>
    >>> binascii.hexlify(enc) == hexenc
    True


XXTEA Type
-----------

The ``XXTEA`` type holds a 16-byte key, rounds, and padding setting,
so you can encrypt and decrypt multiple times without passing them each call.

.. code-block:: python

    >>> from xxtea import XXTEA, Padding
    >>>
    >>> cipher = XXTEA(key, padding=False, rounds=128)
    >>> cipher
    <xxtea.XXTEA object at 0x...>
    >>>
    >>> enc = cipher.encrypt(b'12345678')
    >>> cipher.decrypt(enc)
    b'12345678'
    >>>
    >>> hexenc = cipher.encrypt_hex(b'12345678')
    >>> cipher.decrypt_hex(hexenc)
    b'12345678'

``rounds`` defaults to ``0`` (auto), ``padding`` defaults to ``True``.
``rounds=0`` means ``6 + 52 / n``, where n is the number of 32-bit words in the data.
They are stored on the object and used by every ``encrypt()``, ``decrypt()``,
``encrypt_hex()``, and ``decrypt_hex()`` call:

.. code-block:: python

    >>> c = XXTEA(key)                                 # rounds=0, padding=Padding.PKCS7_4_MIN8
    >>> c = XXTEA(key, rounds=64)                      # override rounds
    >>> c = XXTEA(key, padding=False)                  # disable padding
    >>> c = XXTEA(key, padding=Padding.PKCS7_8)        # 8-byte PKCS#7
    >>> c = XXTEA(key, padding=False, rounds=42)


``encrypt_hex()`` and ``decrypt_hex()`` operate on ciphertext in a hexadecimal
representation. They are exactly equivalent to:

.. code-block:: python

    >>> hexenc = binascii.hexlify(xxtea.encrypt(s, key))
    >>> s == xxtea.decrypt(binascii.unhexlify(hexenc), key)
    True


Padding
---------

``padding`` is an ``xxtea.Padding`` enum (a ``str`` enum), so more
schemes can be added later. Strings, ``True``, and ``False`` still work:

* ``True`` / ``Padding.PKCS7_4_MIN8`` / ``"pkcs7_4_min8"`` (default):
  4-byte PKCS#7-like, padded to at least 8 bytes. Compatible with
  previous versions of this package. Not standard 4-byte PKCS#7.
* ``Padding.PKCS7_8`` / ``"pkcs7_8"``: Standard **8-byte** PKCS#7,
  compatible with Python `xxteang <https://github.com/ifduyue/xxteang>`_.
* ``False`` / ``None`` / ``Padding.NONE`` / ``"none"``: No padding (raw XXTEA).

``xxtea.PKCS7_4_MIN8`` and ``xxtea.PKCS7_8`` are aliases for the enum
members. They are also available as ``XXTEA.PKCS7_4_MIN8`` and
``XXTEA.PKCS7_8``.

Unknown scheme names raise ``ValueError``. Other values still follow
Python truthiness for compatibility (``0`` / ``""`` / empty containers
disable padding; ``1`` and other truthy non-strings use the default
scheme), but emit a ``DeprecationWarning`` and will be removed in the
next major version. Use ``True``, ``False``, ``None``, or ``Padding``.

The default ``"pkcs7_4_min8"`` scheme uses pad byte value
``4 - (len(data) & 3)`` (range 1–4), plus an extra 4 bytes when the
input is shorter than 4 bytes to meet XXTEA's 2-word minimum
(producing pad values 5–8). Standard 4-byte PKCS#7 never uses pad
values 5–8. Because padding always adds at least one byte, encrypting
an 8-byte input produces a 12-byte ciphertext.

8-byte PKCS#7 uses pad byte value ``8 - (len(data) & 7)`` (range 1–8).
Encrypting an 8-byte input produces a 16-byte ciphertext.

.. code-block:: python

    >>> xxtea.decrypt_hex(xxtea.encrypt_hex(b'', key), key)
    b''
    >>> xxtea.decrypt_hex(xxtea.encrypt_hex(b' ', key), key)
    b' '
    >>> len(xxtea.encrypt(b'12345678', key))                          # PKCS7_4_MIN8
    12
    >>> len(xxtea.encrypt(b'12345678', key, padding=xxtea.PKCS7_8))   # PKCS7_8
    16

You can disable padding by setting padding parameter to ``False``.
In this case data will not be padded, so data length must be a multiple of 4 bytes and must not be less than 8 bytes.
Otherwise ``ValueError`` will be raised:

.. code-block:: python

    >>> xxtea.encrypt_hex(b'', key, padding=False)
    ValueError: Data length must be a multiple of 4 bytes and must not be less than 8 bytes
    >>> xxtea.encrypt_hex(b'xxtea is good', key, padding=False)
    ValueError: Data length must be a multiple of 4 bytes and must not be less than 8 bytes
    >>> xxtea.decrypt_hex(xxtea.encrypt_hex(b'12345678', key, padding=False), key, padding=False)
    b'12345678'


Rounds
----------

By default xxtea manipulates the input data for ``6 + 52 / n`` rounds,
where n denotes how many 32-bit integers the input data can fit in.
We can change this by setting ``rounds`` parameter.

Do note that the more rounds it is, the more time will be consumed.
``rounds`` must fit in a 32-bit unsigned integer; values exceeding
``2**32 - 1`` raise ``OverflowError``.

.. code-block:: python

    >>> import xxtea
    >>> import string
    >>> data = string.digits.encode()
    >>> key = string.ascii_letters[:16].encode()
    >>> xxtea.encrypt_hex(data, key)
    b'5b80b08a5d1923e4cd992dd5'
    >>> 6 + 52 // ((len(data) + (4 - 1)) // 4)  # 4 means 4 bytes, size of a 32-bit integer
    23
    >>> xxtea.encrypt_hex(data, key, rounds=23)
    b'5b80b08a5d1923e4cd992dd5'
    >>> xxtea.encrypt_hex(data, key, rounds=1024)
    b'1577bbf28c43ced93bd50720'


Catching Exceptions
---------------------

When calling these functions, a ``ValueError``, ``TypeError``, or ``OverflowError``
may be raised.  Note that invalid hex input raises ``binascii.Error``, which is
a subclass of ``ValueError``:

.. code-block:: python

    >>> import xxtea
    >>> from xxtea import XXTEA
    >>>
    >>> def try_catch(func, *args, **kwargs):
    ...     try:
    ...         func(*args, **kwargs)
    ...     except Exception as e:
    ...         print(e.__class__.__name__, ':', e)
    ...
    ...
    ...
    >>> try_catch(xxtea.decrypt, b'', key=b'')
    ValueError : Need a 16-byte key.
    >>> try_catch(xxtea.decrypt, b'', key=b' '*16)
    ValueError : Data length must be a multiple of 4 bytes and must not be less than 8 bytes
    >>> try_catch(xxtea.decrypt, b' '*8, key=b' '*16)
    ValueError : Invalid data, illegal padding. Could be using a wrong key.
    >>> try_catch(xxtea.decrypt_hex, b' '*8, key=b' '*16)
    Error : Non-hexadecimal digit found
    >>> try_catch(xxtea.decrypt_hex, b'abc', key=b' '*16)
    Error : Odd-length string
    >>> try_catch(xxtea.decrypt_hex, b'abcd', key=b' '*16)
    ValueError : Data length must be a multiple of 4 bytes and must not be less than 8 bytes
    >>> try_catch(xxtea.encrypt, b'x', b'k'*16, rounds=2**32)
    OverflowError : rounds value too large
    >>> try_catch(XXTEA, key=b'short')
    ValueError : Need a 16-byte key.
    >>> try_catch(XXTEA, key=b'k'*16, rounds=2**32)
    OverflowError : rounds value too large
