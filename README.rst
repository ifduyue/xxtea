xxtea
=====

Description
------------
xxtea implemented in pure Python

Installation
-------------
::
    
    $ pip install xxtea -U


Example
-----------
::

    from xxtea import decrypt, encrypt
    
    key = "hey, lyxint"
    s = "what's up, dude??"
    
    enc = encrypt(s, key, True)
    dec = decrypt(enc, key, True)
    
    print len(enc), enc
    print len(dec), dec
    assert s == dec

