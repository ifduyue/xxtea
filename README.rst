xxtea
=====

.. image:: https://travis-ci.org/ifduyue/xxtea.png
    :target: https://travis-ci.org/ifduyue/xxtea

xxtea implemented as a Python extension module.

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

