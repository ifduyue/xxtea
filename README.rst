xxtea
=====

.. image:: https://travis-ci.org/ifduyue/xxtea.png
    :target: https://travis-ci.org/ifduyue/xxtea

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
which is required by The XXTEA_ algorithm). As a result of these mesures,
you can encrypt not only texts, but also any binary bytes of any length.


Installation
-------------
::
    
    $ pip install xxtea -U


Example
-----------
.. code-block:: python

    import os
    from xxtea import decrypt, encrypt

    key = os.urandom(16)  # Key must be a 16-byte string.
    s = "xxtea is good"

    enc = encrypt(s, key)
    dec = decrypt(enc, key)
    
    print len(enc), enc
    print len(dec), dec
    assert s == dec

