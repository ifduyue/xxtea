xxtea |travis-badge| |appveyor-badge| |pypi-badge| |supported-pythons-badge| |license-badge|
==============================================================================================

.. |travis-badge| image:: https://travis-ci.org/ifduyue/xxtea.svg
   :target: https://travis-ci.org/ifduyue/xxtea

.. |appveyor-badge| image:: https://ci.appveyor.com/api/projects/status/mitcnsayvbr10gt4?svg=true
   :target: https://ci.appveyor.com/project/duyue/xxtea
   :alt: Appveyor Build Status

.. |pypi-badge| image:: https://img.shields.io/pypi/v/xxtea.svg
   :target: https://pypi.python.org/pypi/xxtea
   :alt: Latest Version

.. |supported-pythons-badge| image:: https://img.shields.io/pypi/pyversions/xxtea.svg
    :target: https://pypi.python.org/pypi/xxtea
    :alt: Supported Python versions

.. |license-badge| image:: https://img.shields.io/pypi/l/xxtea.svg
    :target: https://pypi.python.org/pypi/xxtea
    :alt: License

.. _XXTEA: http://en.wikipedia.org/wiki/XXTEA
.. _longs2bytes: https://github.com/ifduyue/xxtea/blob/master/xxtea.c#L130
.. _bytes2longs: https://github.com/ifduyue/xxtea/blob/master/xxtea.c#L102
.. _PKCS#7: http://en.wikipedia.org/wiki/Padding_%28cryptography%29#PKCS7

XXTEA_ implemented as a Python extension module, licensed under 2-clause BSD.

The XXTEA_ algorithm takes a 128-bit key and operates on an array of 32-bit
integers (at least 2 integers), but it doesn't define the conversions between
bytes and array. Due to this reason, many XXTEA implementations out there are
not compatible with each other.

In this implementation,  the conversions between bytes and array are
taken care of by longs2bytes_ and bytes2longs_. `PKCS#7`_ padding is also used
to make sure that the input bytes are padded to multiple of 4-byte (the size
of a 32-bit integer) and at least 8-byte long (the size of two 32-bit integer,
which is required by the XXTEA_ algorithm). As a result of these measures,
you can encrypt not only texts, but also any binary bytes of any length.


Installation
-------------

::

    $ pip install xxtea -U


Usage
-----------

This module provides four functions: ``encrypt()``, ``decrypt()``,
``encrypt_hex()``, and ``decrypt_hex()``.

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
    >>> hexenc
    b'7ad85672d770fb5cf636c49d57e732ae'
    >>> s == xxtea.decrypt_hex(hexenc, key)
    True
    >>>
    >>> binascii.hexlify(enc) == hexenc
    True


``encrypt_hex()`` and ``decrypt_hex()`` operate on ciphertext in a hexadecimal
representation. They are exactly equivalent to:

.. code-block:: python

    >>> hexenc = binascii.hexlify(xxtea.encrypt(s, key))
    >>> s == xxtea.decrypt(binascii.unhexlify(hexenc), key)
    True


Padding
---------

Padding is enabled by default, in this case you can encode any bytes of any length.

.. code-block:: python

    >>> xxtea.encrypt_hex('', key)
    b'd63256eb59134f1f'
    >>> xxtea.decrypt_hex(_, key)
    b''
    >>> xxtea.encrypt_hex(' ', key)
    b'97009bd24074a7a5'
    >>> xxtea.decrypt_hex(_, key)
    b' '

You can disable padding by setting padding parameter to ``False``.
In this case data will not be padded, so data length must be a multiple of 4 bytes and must not be less than 8 bytes.
Otherwise ``ValueError`` will be raised:

.. code-block:: python

    >>> xxtea.encrypt_hex('', key, padding=False)
    ValueError: Data length must be a multiple of 4 bytes and must not be less than 8 bytes
    >>> xxtea.encrypt_hex('xxtea is good', key, padding=False)
    ValueError: Data length must be a multiple of 4 bytes and must not be less than 8 bytes
    >>> xxtea.encrypt_hex('12345678', key, padding=False)
    b'64f4e969ba90d386'
    >>> xxtea.decrypt_hex(_, key, padding=False)
    b'12345678'


Rounds
----------

By default xxtea manipulates the input data for ``6 + 52 / n`` rounds,
where n denotes how many 32-bit integers the input data can fit in.
We can change this by setting ``rounds`` parameter.

Do note that the more rounds it is, the more time will be consumed.

.. code-block:: python

    >>> import xxtea
    >>> import string
    >>> data = string.digits
    >>> key = string.ascii_letters[:16]
    >>> xxtea.encrypt_hex(data, key)
    b'5b80b08a5d1923e4cd992dd5'
    >>> 6 + 52 // ((len(data) + (4 - 1)) // 4)
    23
    >>> xxtea.encrypt_hex(data, key, rounds=23)
    b'5b80b08a5d1923e4cd992dd5'
    >>> xxtea.encrypt_hex(data, key, rounds=1024)
    b'1577bbf28c43ced93bd50720'


Catching Exceptions
---------------------

When calling ``decrypt()`` and ``decrypt_hex()``, it is possible that a ``ValueError`` or a ``TypeError``
was raised. Better to catch them, or your program will exit.

.. code-block:: python

    >>> from __future__ import print_function
    >>> import xxtea
    >>>
    >>> def try_catch(func, *args, **kwargs):
    ...     try:
    ...         func(*args, **kwargs)
    ...     except Exception as e:
    ...         print(e.__class__.__name__, ':', e)
    ...
    ...
    ...
    >>> try_catch(xxtea.decrypt, '', key='')
    ValueError : Need a 16-byte key.
    >>> try_catch(xxtea.decrypt, '', key=' '*16)
    ValueError : Invalid data, data length is not a multiple of 4, or less than 8.
    >>> try_catch(xxtea.decrypt, ' '*8, key=' '*16)
    ValueError : Invalid data, illegal PKCS#7 padding. Could be using a wrong key.
    >>> try_catch(xxtea.decrypt_hex, ' '*8, key=' '*16)
    TypeError : Non-hexadecimal digit found
    >>> try_catch(xxtea.decrypt_hex, 'abc', key=' '*16)
    TypeError : Odd-length string
    >>> try_catch(xxtea.decrypt_hex, 'abcd', key=' '*16)
    ValueError : Invalid data, data length is not a multiple of 4, or less than 8.
