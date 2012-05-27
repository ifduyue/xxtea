#coding: utf8

__version__ = '0.0.1'
__author__ = 'Elyes Du <lyxint@gmail.com>'
__url__ = 'https://github.com/lyxint/xxtea'

try:
    import binascii.b2a_hex as str2hex
    import binascii.a2b_hex as hex2str
except ImportError:

    def hex2str(s):
        length = len(s)
        result = ''
        for i in xrange(0, length, 2):
            result += chr(int(s[i:i+2], 16))
        return result

    def str2hex(s):
        table = "0123456789abcdef"
        length = len(s)
        result = ''
        for i in xrange(length):
            result += table[ord(s[i])>>4] + table[ord(s[i])&0xF]
        return result


def str2longs(s):
    length = (len(s) + 3) / 4
    s = s.ljust(length*4, '\0')
    result = []
    for i in xrange(length):
        j = 0
        j |= ord(s[i*4])
        j |= ord(s[i*4+1])<<8
        j |= ord(s[i*4+2])<<16
        j |= ord(s[i*4+3])<<24
        result.append(j)
    return result

def longs2str(s):
    result = ""
    for c in s:
        result += chr(c&0xFF) + chr(c>>8&0xFF)\
               + chr(c>>16&0xFF) + chr(c>>24&0xFF)
    return result.rstrip('\0')
    
def btea(v, n, k):
    if not isinstance(v, list) or \
        not isinstance(n, int) or \
        not isinstance(k, (list, tuple)):
        return False

    MX = lambda: ((z>>5)^(y<<2)) + ((y>>3)^(z<<4))^(sum^y) + (k[(p & 3)^e]^z)
    u32 = lambda x: x & 0xffffffff

    y = v[0]
    sum = 0
    DELTA = 0x9e3779b9
    if n > 1: 
        z = v[n-1]
        q = 6 + 52 / n
        while q > 0:
            q -= 1
            sum = u32(sum + DELTA)
            e = u32(sum >> 2) & 3
            p = 0
            while p < n - 1:
                y = v[p+1]
                z = v[p] = u32(v[p] + MX())
                p += 1
            y = v[0]
            z = v[n-1] = u32(v[n-1] + MX())
        return True
    elif n < -1:
        n = -n
        q = 6 + 52 / n
        sum = u32(q * DELTA)
        while sum != 0:
            e = u32(sum >> 2) & 3
            p = n - 1
            while p > 0:
                z = v[p-1]
                y = v[p] = u32(v[p] - MX())
                p -= 1
            z = v[n-1]
            y = v[0] = u32(v[0] - MX())
            sum = u32(sum - DELTA)
        return True
    return False

def encrypt(str, key, returnhex=True):
    key = key.ljust(16, '\0')
    v = str2longs(str)
    k = str2longs(key)
    n = len(v)
    btea(v, n, k)
    
    result = longs2str(v)
    if (returnhex):
        result = str2hex(result)
    return result
            
def decrypt(s, key, ishex=True):
    key = key.ljust(16, '\0')
    if (ishex):
        s = hex2str(s)
    v = str2longs(s)
    k = str2longs(key)
    n = len(v)
    
    btea(v, -n, k)
    
    return longs2str(v)
    
    
if __name__ == '__main__':
    key = "hey, lyxint"
    s = "what's up, dude??"
    enc = encrypt(s, key, True)
    dec = decrypt(enc, key, True)
    print len(enc), enc
    print len(dec), dec
    assert s == dec
    
