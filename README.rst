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

    from xxtea import decrypt, encrypt
    
    key = "xxtea is good"
    s = "xxtea is really good"
    
    enc = encrypt(s, key)
    dec = decrypt(enc, key)
    
    print len(enc), enc
    print len(dec), dec
    assert s == dec

