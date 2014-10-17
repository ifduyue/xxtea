xxtea
=====

Description
------------
xxtea implemented as a Python extension module.

Installation
-------------
::
    
    $ pip install xxtea -U


Example
-----------
::

    from xxtea import decrypt, encrypt
    
    key = "xxtea is good"
    s = "xxtea is really good"
    
    enc = encrypt(s, key)
    dec = decrypt(enc, key)
    
    print len(enc), enc
    print len(dec), dec
    assert s == dec

