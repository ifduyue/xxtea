import os
import sys
import timeit
import xxtea


if __name__ == '__main__':
    try:
        length = int(sys.argv[1])
        times = int(sys.argv[2])
    except:
        print >> sys.stderr, 'Usage: {} datalength times'.format(sys.argv[0])
        sys.exit(-1)

    testkey = os.urandom(16)
    testdata = os.urandom(length)
    t = timeit.Timer('encrypt({}, {})'.format(repr(testdata), repr(testkey)), 'from xxtea import encrypt')
    print 'encrypt', t.timeit(times)
    testdata = xxtea.encrypt(testdata, testkey)
    t = timeit.Timer('decrypt({}, {})'.format(repr(testdata), repr(testkey)), 'from xxtea import decrypt')
    print 'decrypt', t.timeit(times)

