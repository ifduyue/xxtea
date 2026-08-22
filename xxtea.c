/*
 * Copyright (c) 2014-2026, Yue Du
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice,
 *       this list of conditions and the following disclaimer in the documentation
 *       and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Default ciphertext uses "pkcs7_4_min8" padding (4-byte PKCS#7-like, pad+4
 * for inputs shorter than 4 bytes).  padding="pkcs7_8" uses 8-byte PKCS#7,
 * compatible with Python xxteang (https://github.com/ifduyue/xxteang).
 */


#include <Python.h>
#include <stdint.h>
#include <string.h>

#define VERSION "6.1.0"

enum {
    XXTEA_PADDING_NONE = 0,
    XXTEA_PADDING_LENGTH_WORD_SUFFIX = 1,
    XXTEA_PADDING_PKCS7_4_MIN8 = 4,
    XXTEA_PADDING_PKCS7_8 = 8,
};

#define DELTA 0x9e3779b9U
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

typedef struct xxtea_mod_state {
    PyObject *binascii_hexlify;
    PyObject *binascii_unhexlify;
} xxtea_mod_state;

static inline void btea(uint32_t *v, int n, uint32_t const key[4], unsigned int rounds)
{
    uint32_t y, z, sum;
    unsigned p, e;

    if (n > 1) {          /* Coding Part */
        rounds = rounds == 0 ? (unsigned)(6 + 52 / n) : rounds;
        sum = 0;
        z = v[n - 1];

        do {
            sum += DELTA;
            e = (sum >> 2) & 3;

            for (p = 0; p < (unsigned)(n - 1); p++) {
                y = v[p + 1];
                z = v[p] += MX;
            }

            y = v[0];
            z = v[n - 1] += MX;
        }
        while (--rounds);
    }
    else if (n < -1) {    /* Decoding Part */
        n = -n;
        rounds = rounds == 0 ? (unsigned)(6 + 52 / n) : rounds;
        sum = (uint32_t)(rounds * DELTA);
        y = v[0];

        do {
            e = (sum >> 2) & 3;

            for (p = (unsigned)(n - 1); p > 0; p--) {
                z = v[p - 1];
                y = v[p] -= MX;
            }

            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        }
        while (--rounds);
    }
}

static void bytes2longs(const char *in, Py_ssize_t inlen, uint32_t *out, int padding)
{
    Py_ssize_t i, nwords;
    int pad;
    const unsigned char *s = (const unsigned char *)in;

    /* Fast path: process 4 bytes at a time */
    nwords = inlen >> 2;
    for (i = 0; i < nwords; i++) {
#if PY_LITTLE_ENDIAN
        memcpy(&out[i], s + 4 * i, 4);
#else
        const unsigned char *p = s + 4 * i;
        out[i] = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
#endif
    }

    i = nwords << 2;

    if (padding == XXTEA_PADDING_LENGTH_WORD_SUFFIX) {
        /*
         * Length-word suffix, the layout used by Cocos Creator JSC
         * files: zero-pad the final partial word, then append one word
         * holding the original byte length.  XXTEA needs two words, so
         * empty input gets an extra zero word before the length word.
         */
        uint32_t w = 0;
        int shift = 0;
        for (; i < inlen; i++, shift += 8) {
            w |= (uint32_t)s[i] << shift;
        }
        if ((inlen & 3) != 0) {
            out[nwords] = w;
            nwords++;
        }
        if (nwords < 1) {
            out[nwords++] = 0;
        }
        /* Numeric uint32, not memcpy(&inlen): 64-bit big-endian would
         * copy the high half.  Ciphertext length word is little-endian. */
        out[nwords] = (uint32_t)inlen;
        return;
    }

    if (padding == XXTEA_PADDING_PKCS7_8) {
        /*
         * 8-byte PKCS#7 (xxteang): pad = 8 - (len & 7), range 1-8.
         * Completes the partial word, then adds a whole extra pad word
         * unless the length is 4 mod 8.
         */
        uint32_t w = 0;
        int r = (int)(inlen & 3);
        int shift = 0;
        uint32_t pw;
        for (; i < inlen; i++, shift += 8) {
            w |= (uint32_t)s[i] << shift;
        }
        pad = 8 - (int)(inlen & 7);
        pw = (uint32_t)pad * 0x01010101u;
        w |= pw & (~0u << (8 * r));
        out[nwords] = w;
        if ((inlen & 4) == 0) {
            out[nwords + 1] = pw;
        }
        return;
    }

    /*
     * pkcs7_4_min8 (default): 4-byte PKCS#7-like, but inputs shorter
     * than 4 bytes are padded to two words (pad values 5-8) for XXTEA's
     * 2-word minimum.  Not standard PKCS#7.
     */
    if (padding == XXTEA_PADDING_PKCS7_4_MIN8 || (inlen & 3) != 0) {
        uint32_t w = 0;
        int r = (int)(inlen & 3);
        int shift = 0;
        for (; i < inlen; i++, shift += 8) {
            w |= (uint32_t)s[i] << shift;
        }
        if (padding == XXTEA_PADDING_PKCS7_4_MIN8) {
            pad = 4 - r;
            if (inlen < 4) {
                pad += 4;
            }
            w |= (uint32_t)pad * 0x01010101u & (~0u << (8 * r));
            if (inlen < 4) {
                out[nwords + 1] = (uint32_t)pad * 0x01010101u;
            }
        }
        out[nwords] = w;
    }
}

static Py_ssize_t longs2bytes(const uint32_t *in, Py_ssize_t inlen, char *out, int padding)
{
    Py_ssize_t i, outlen;
    int pad;
    unsigned char *s = (unsigned char *)out;

#if PY_LITTLE_ENDIAN
    /* Callers always pass the same buffer; words are already LE bytes. */
    (void)in;
#else
    /*
     * Big endian: write each word as little-endian bytes.  Snapshot the
     * whole word first because in and out alias.
     */
    for (i = 0; i < inlen; i++) {
        uint32_t word = in[i];
        s[4 * i]     = (unsigned char)(word & 0xFF);
        s[4 * i + 1] = (unsigned char)((word >> 8) & 0xFF);
        s[4 * i + 2] = (unsigned char)((word >> 16) & 0xFF);
        s[4 * i + 3] = (unsigned char)((word >> 24) & 0xFF);
    }
#endif

    outlen = inlen * 4;

    /* Length-word suffix: the last word is the original byte length. */
    if (padding == XXTEA_PADDING_LENGTH_WORD_SUFFIX) {
        Py_ssize_t n = outlen - 4;
        Py_ssize_t leftover;
        uint32_t m32 = (uint32_t)s[n] | ((uint32_t)s[n + 1] << 8) |
                       ((uint32_t)s[n + 2] << 16) | ((uint32_t)s[n + 3] << 24);
        leftover = n - (Py_ssize_t)m32;
        /* 0-3 zero-pad bytes, or 4 zero bytes when empty input was
         * padded to the XXTEA 2-word minimum. */
        if (m32 > (uint32_t)n || leftover < 0 ||
            (leftover > 3 && !(m32 == 0 && leftover == 4))) {
            /* invalid padding */
            return -1;
        }
        for (i = (Py_ssize_t)m32; i < n; i++) {
            if (s[i] != 0) {
                return -1;
            }
        }
        outlen = (Py_ssize_t)m32;
    }
    /* PKCS#7-style unpadding (4-byte or 8-byte; pad values 1-8). */
    else if (padding) {
        pad = s[outlen - 1];
        outlen -= pad;

        if (pad < 1 || pad > 8) {
            /* invalid padding */
            return -1;
        }

        if (outlen < 0) {
            return -2;
        }

        for (i = outlen; i < inlen * 4; i++) {
            if (s[i] != pad) {
                return -3;
            }
        }
    }

    s[outlen] = '\0';

    return outlen;
}

/*****************************************************************************
 * Module Functions ***********************************************************
 ****************************************************************************/

typedef PyObject *(*xxtea_crypt_func)(const char *, Py_ssize_t,
                                      const char *, int, unsigned int);

static inline int
_parse_rounds(PyObject *obj, unsigned int *rounds)
{
    unsigned long val = PyLong_AsUnsignedLong(obj);
    if (val == (unsigned long)-1 && PyErr_Occurred())
        return -1;
    if (val > UINT_MAX) {
        PyErr_SetString(PyExc_OverflowError, "rounds value too large");
        return -1;
    }
    *rounds = (unsigned int)val;
    return 0;
}

static int
_warn_legacy_padding(PyObject *obj)
{
    return PyErr_WarnFormat(
        PyExc_DeprecationWarning, 1,
        "padding=%R is deprecated; use True, False, None, or xxtea.Padding "
        "(PKCS7_4_MIN8, PKCS7_8, LENGTH_WORD_SUFFIX, NONE). "
        "This will be removed in the next major version.",
        obj);
}

static inline int
_parse_padding_name(PyObject *name, int *padding)
{
    if (PyUnicode_GET_LENGTH(name) == 0) {
        if (_warn_legacy_padding(name) < 0)
            return -1;
        *padding = XXTEA_PADDING_NONE;
        return 0;
    }
    if (PyUnicode_CompareWithASCIIString(name, "pkcs7_4_min8") == 0) {
        *padding = XXTEA_PADDING_PKCS7_4_MIN8;
        return 0;
    }
    if (PyUnicode_CompareWithASCIIString(name, "pkcs7_8") == 0) {
        *padding = XXTEA_PADDING_PKCS7_8;
        return 0;
    }
    if (PyUnicode_CompareWithASCIIString(name, "length_word_suffix") == 0) {
        *padding = XXTEA_PADDING_LENGTH_WORD_SUFFIX;
        return 0;
    }
    if (PyUnicode_CompareWithASCIIString(name, "none") == 0) {
        *padding = XXTEA_PADDING_NONE;
        return 0;
    }
    PyErr_Format(PyExc_ValueError,
        "unknown padding %R (expected Padding.NONE, Padding.PKCS7_4_MIN8, "
        "Padding.PKCS7_8, or Padding.LENGTH_WORD_SUFFIX)",
        name);
    return -1;
}

static inline int
_parse_padding(PyObject *obj, int *padding)
{
    if (obj == Py_True) {
        *padding = XXTEA_PADDING_PKCS7_4_MIN8;
        return 0;
    }
    if (obj == Py_False || obj == Py_None) {
        *padding = XXTEA_PADDING_NONE;
        return 0;
    }
    if (PyUnicode_Check(obj)) {
        return _parse_padding_name(obj, padding);
    }

    /* Padding enum members (and any enum-like object with a str .value). */
    PyObject *value = PyObject_GetAttrString(obj, "value");
    if (value != NULL) {
        int rc;
        if (PyUnicode_Check(value)) {
            rc = _parse_padding_name(value, padding);
            Py_DECREF(value);
            return rc;
        }
        Py_DECREF(value);
    }
    else if (PyErr_ExceptionMatches(PyExc_AttributeError)) {
        PyErr_Clear();
    }
    else {
        return -1;
    }

    /* Historical: any other object uses truthiness (0/empty → none,
     * 1/nonempty → pkcs7_4_min8).  Deprecated; removed in the next major. */
    if (_warn_legacy_padding(obj) < 0)
        return -1;
    int res = PyObject_IsTrue(obj);
    if (res < 0)
        return -1;
    *padding = res ? XXTEA_PADDING_PKCS7_4_MIN8 : XXTEA_PADDING_NONE;
    return 0;
}

/*
 * Parse all arguments in a single pass.  Returns 0 on success, -1 on error.
 */
static inline int
_parse_args(PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames,
            PyObject **data_obj, PyObject **key_obj,
            int *padding, unsigned int *rounds)
{
    int data_set = 0, key_set = 0, padding_set = 0, rounds_set = 0;

    *data_obj = *key_obj = NULL;
    *padding = XXTEA_PADDING_PKCS7_4_MIN8;
    *rounds = 0;

    /* Positional: data, key */
    if (nargs > 0) { *data_obj = args[0]; data_set = 1; }
    if (nargs > 1) { *key_obj  = args[1]; key_set  = 1; }

    if (nargs > 4) {
        PyErr_SetString(PyExc_TypeError,
            "function takes at most 4 positional arguments");
        return -1;
    }

    /* Keyword loop */
    if (kwnames != NULL) {
        Py_ssize_t nkwargs = PyTuple_GET_SIZE(kwnames);
        for (Py_ssize_t i = 0; i < nkwargs; i++) {
            PyObject *name = PyTuple_GET_ITEM(kwnames, i);
            PyObject *value = args[nargs + i];

            if (PyUnicode_CompareWithASCIIString(name, "data") == 0) {
                if (data_set) { PyErr_SetString(PyExc_TypeError,
                    "argument 'data' given both as positional and keyword");
                    return -1; }
                *data_obj = value;
                data_set = 1;
            }
            else if (PyUnicode_CompareWithASCIIString(name, "key") == 0) {
                if (key_set) { PyErr_SetString(PyExc_TypeError,
                    "argument 'key' given both as positional and keyword");
                    return -1; }
                *key_obj = value;
                key_set = 1;
            }
            else if (PyUnicode_CompareWithASCIIString(name, "padding") == 0) {
                if (nargs > 2) { PyErr_SetString(PyExc_TypeError,
                    "argument 'padding' given both as positional and keyword");
                    return -1; }
                if (_parse_padding(value, padding) < 0)
                    return -1;
                padding_set = 1;
            }
            else if (PyUnicode_CompareWithASCIIString(name, "rounds") == 0) {
                if (nargs > 3) { PyErr_SetString(PyExc_TypeError,
                    "argument 'rounds' given both as positional and keyword");
                    return -1; }
                if (_parse_rounds(value, rounds) < 0)
                    return -1;
                rounds_set = 1;
            }
            else {
                PyErr_Format(PyExc_TypeError,
                    "'%U' is an invalid keyword argument", name);
                return -1;
            }
        }
    }

    /* Positional: padding, rounds (only if not set via keyword) */
    if (nargs > 2 && !padding_set) {
        if (_parse_padding(args[2], padding) < 0)
            return -1;
    }
    if (nargs > 3 && !rounds_set) {
        if (_parse_rounds(args[3], rounds) < 0)
            return -1;
    }

    if (!*data_obj || !*key_obj) {
        PyErr_Format(PyExc_TypeError,
            "function missing required arguments: 'data' and 'key'");
        return -1;
    }

    return 0;
}

static inline PyObject *
_call_one_arg(PyObject *func, PyObject *arg)
{
    if (func == NULL) {
        PyErr_SetString(PyExc_RuntimeError, "module state not available");
        return NULL;
    }
    return PyObject_CallOneArg(func, arg);
}

/* Acquire buffers and validate key length. Returns 0 on success, -1 on error. */
static inline int
_get_buffers(PyObject *data_obj, PyObject *key_obj,
             Py_buffer *data, Py_buffer *key)
{
    if (PyObject_GetBuffer(data_obj, data, PyBUF_SIMPLE) < 0)
        return -1;
    if (PyObject_GetBuffer(key_obj, key, PyBUF_SIMPLE) < 0) {
        PyBuffer_Release(data);
        return -1;
    }
    if (key->len != 16) {
        PyErr_SetString(PyExc_ValueError, "Need a 16-byte key.");
        PyBuffer_Release(data);
        PyBuffer_Release(key);
        return -1;
    }
    return 0;
}

static inline PyObject *
_call_module_crypt(PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames,
                   xxtea_crypt_func crypt)
{
    Py_buffer data = {NULL}, key = {NULL};
    PyObject *data_obj, *key_obj;
    int padding;
    unsigned int rounds;

    if (_parse_args(args, nargs, kwnames, &data_obj, &key_obj, &padding, &rounds) < 0)
        return NULL;
    if (_get_buffers(data_obj, key_obj, &data, &key) < 0)
        return NULL;

    PyObject *retval = crypt(data.buf, data.len, key.buf, padding, rounds);
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    return retval;
}

/*
 * Internal encrypt implementation — takes raw buffers, returns PyBytes or NULL.
 *
 * Writes directly into the PyBytes object's internal buffer to avoid an
 * intermediate heap allocation and an extra longs->bytes copy.
 */
static inline PyObject *
_encrypt_impl(const char *data_buf, Py_ssize_t data_len,
              const char *key_buf, int padding, unsigned int rounds)
{
    uint32_t k[4] = {0};

    if (!padding && (data_len < 8 || (data_len & 3) != 0)) {
        PyErr_SetString(PyExc_ValueError,
            "Data length must be a multiple of 4 bytes and must not be less than 8 bytes");
        return NULL;
    }

    Py_ssize_t alen;
    if (padding == XXTEA_PADDING_LENGTH_WORD_SUFFIX) {
        /* Length word is uint32.  Compiled out on 32-bit, where
         * Py_ssize_t cannot exceed UINT32_MAX (the comparison would
         * warn as always false). */
#if SIZEOF_SIZE_T > 4
        if ((size_t)data_len > 0xFFFFFFFFu) {
            PyErr_SetString(PyExc_OverflowError, "data too large");
            return NULL;
        }
#endif
        if (data_len > PY_SSIZE_T_MAX - 4) {
            PyErr_SetString(PyExc_OverflowError, "data too large");
            return NULL;
        }
        alen = (data_len >> 2) + ((data_len & 3) != 0) + 1;
        if (alen < 2) {
            alen = 2;
        }
    }
    else if (padding == XXTEA_PADDING_PKCS7_8) {
        if (data_len > PY_SSIZE_T_MAX - 8) {
            PyErr_SetString(PyExc_OverflowError, "data too large");
            return NULL;
        }
        alen = ((data_len & ~(Py_ssize_t)7) + 8) >> 2;
    }
    else if (padding == XXTEA_PADDING_PKCS7_4_MIN8) {
        alen = data_len < 4 ? 2 : (data_len >> 2) + 1;
    }
    else {
        alen = data_len >> 2;
    }
    if (alen > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError, "data too large");
        return NULL;
    }

    PyObject *retval = PyBytes_FromStringAndSize(NULL, alen << 2);
    if (!retval) {
        return NULL;
    }

    uint32_t *d = (uint32_t *)PyBytes_AsString(retval);

    Py_BEGIN_ALLOW_THREADS
    bytes2longs(data_buf, data_len, d, padding);
    bytes2longs(key_buf, 16, k, 0);
    btea(d, (int)alen, k, rounds);
#if !PY_LITTLE_ENDIAN
    /*
     * On a big-endian host the raw uint32_t memory layout in the PyBytes
     * buffer would be big-endian, but we want the ciphertext to be
     * little-endian on the wire.  Rewrite the buffer word-by-word as
     * little-endian bytes (safe because we read each word before writing
     * its bytes).
     */
    longs2bytes(d, alen, (char *)d, 0);
#endif
    Py_END_ALLOW_THREADS

    return retval;
}

/*
 * Internal decrypt implementation — takes raw buffers, returns PyBytes or NULL.
 *
 * The ciphertext length is already a multiple of 4 and >= 8, so we decrypt
 * in place inside the output PyBytes object and then shrink it if padding
 * is enabled.
 */
static inline PyObject *
_decrypt_impl(const char *data_buf, Py_ssize_t data_len,
              const char *key_buf, int padding, unsigned int rounds)
{
    uint32_t k[4] = {0};

    if (data_len & 3 || data_len < 8) {
        PyErr_SetString(PyExc_ValueError,
            "Data length must be a multiple of 4 bytes and must not be less than 8 bytes");
        return NULL;
    }

    Py_ssize_t alen = data_len / 4;
    if (alen > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError, "data too large");
        return NULL;
    }

    PyObject *retval = PyBytes_FromStringAndSize(NULL, data_len);
    if (!retval) {
        return NULL;
    }

    char *retbuf = PyBytes_AsString(retval);
    Py_ssize_t rc;
    Py_BEGIN_ALLOW_THREADS
    bytes2longs(data_buf, data_len, (uint32_t *)retbuf, 0);
    bytes2longs(key_buf, 16, k, 0);
    btea((uint32_t *)retbuf, -(int)alen, k, rounds);
    rc = longs2bytes((uint32_t *)retbuf, alen, retbuf, padding);
    Py_END_ALLOW_THREADS

    if (padding) {
        if (rc >= 0) {
            /* Remove padding bytes. */
            Py_SET_SIZE(retval, rc);
        }
        else {
            PyErr_SetString(PyExc_ValueError,
                "Invalid data, illegal padding. Could be using a wrong key.");
            Py_DECREF(retval);
            retval = NULL;
        }
    }

    return retval;
}


PyDoc_STRVAR(
    xxtea_encrypt_doc,
    "encrypt(data, key, padding=True, rounds=0)\n\n"
    "Encrypt bytes-like data with a 16-byte key and return bytes.\n"
    "padding: True/Padding.PKCS7_4_MIN8 (default), Padding.PKCS7_8, "
    "Padding.LENGTH_WORD_SUFFIX, or False/None/Padding.NONE.");

static PyObject *
xxtea_encrypt(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    return _call_module_crypt(args, nargs, kwnames, _encrypt_impl);
}


PyDoc_STRVAR(
    xxtea_encrypt_hex_doc,
    "encrypt_hex(data, key, padding=True, rounds=0)\n\n"
    "Encrypt bytes-like data with a 16-byte key and return hex-encoded bytes.\n"
    "padding: True/Padding.PKCS7_4_MIN8 (default), Padding.PKCS7_8, "
    "Padding.LENGTH_WORD_SUFFIX, or False/None/Padding.NONE.");

static PyObject *
xxtea_encrypt_hex(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    PyObject *tmp = _call_module_crypt(args, nargs, kwnames, _encrypt_impl);
    if (!tmp)
        return NULL;

    xxtea_mod_state *state = (xxtea_mod_state*)PyModule_GetState(self);
    PyObject *retval = _call_one_arg(state ? state->binascii_hexlify : NULL, tmp);
    Py_DECREF(tmp);
    return retval;
}


PyDoc_STRVAR(
    xxtea_decrypt_doc,
    "decrypt(data, key, padding=True, rounds=0)\n\n"
    "Decrypt bytes-like data with a 16-byte key and return bytes.\n"
    "padding: True/Padding.PKCS7_4_MIN8 (default), Padding.PKCS7_8, "
    "Padding.LENGTH_WORD_SUFFIX, or False/None/Padding.NONE.");

static PyObject *
xxtea_decrypt(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    return _call_module_crypt(args, nargs, kwnames, _decrypt_impl);
}


PyDoc_STRVAR(
    xxtea_decrypt_hex_doc,
    "decrypt_hex(data, key, padding=True, rounds=0)\n\n"
    "Decrypt hex-encoded data with a 16-byte key and return bytes.\n"
    "padding: True/Padding.PKCS7_4_MIN8 (default), Padding.PKCS7_8, "
    "Padding.LENGTH_WORD_SUFFIX, or False/None/Padding.NONE.");

static PyObject *
xxtea_decrypt_hex(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    Py_buffer data = {NULL}, key = {NULL};
    PyObject *data_obj, *key_obj;
    int padding;
    unsigned int rounds;

    if (_parse_args(args, nargs, kwnames, &data_obj, &key_obj, &padding, &rounds) < 0)
        return NULL;

    xxtea_mod_state *state = (xxtea_mod_state*)PyModule_GetState(self);
    PyObject *tmp = _call_one_arg(state ? state->binascii_unhexlify : NULL, data_obj);
    if (!tmp)
        return NULL;

    if (_get_buffers(tmp, key_obj, &data, &key) < 0) {
        Py_DECREF(tmp);
        return NULL;
    }

    PyObject *retval = _decrypt_impl(data.buf, data.len, key.buf, padding, rounds);
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    Py_DECREF(tmp);
    return retval;
}

/*****************************************************************************
 * XXTEA Type ****************************************************************
 ****************************************************************************/



typedef struct {
    PyObject_HEAD
    char key[16];
    unsigned int rounds;
    int padding;
} xxtea_object;

static PyObject *
_call_object_crypt(xxtea_object *self, PyObject *data, xxtea_crypt_func crypt)
{
    Py_buffer data_buf = {NULL};
    if (PyObject_GetBuffer(data, &data_buf, PyBUF_SIMPLE) < 0)
        return NULL;

    PyObject *retval = crypt(data_buf.buf, data_buf.len,
                             self->key, self->padding, self->rounds);
    PyBuffer_Release(&data_buf);
    return retval;
}

/*
 * Manually parse XXTEA(key, padding=True, rounds=0) for both the
 * vectorcall constructor and the legacy tp_init fallback.
 * Returns 0 on success, -1 on error with an exception set.
 */
static int
_parse_init_args(PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames,
                 PyObject **key_obj, int *padding, unsigned int *rounds)
{
    int key_set = 0;

    *key_obj = NULL;
    *padding = XXTEA_PADDING_PKCS7_4_MIN8;
    *rounds = 0;

    if (nargs > 3) {
        PyErr_SetString(PyExc_TypeError,
            "XXTEA() takes at most 3 positional arguments");
        return -1;
    }

    /* Positional: key, [padding], [rounds] */
    if (nargs > 0) { *key_obj = args[0]; key_set = 1; }

    /* Keyword loop */
    if (kwnames != NULL) {
        Py_ssize_t nkwargs = PyTuple_GET_SIZE(kwnames);
        for (Py_ssize_t i = 0; i < nkwargs; i++) {
            PyObject *name = PyTuple_GET_ITEM(kwnames, i);
            PyObject *value = args[nargs + i];

            if (PyUnicode_CompareWithASCIIString(name, "key") == 0) {
                if (key_set) {
                    PyErr_SetString(PyExc_TypeError,
                        "argument 'key' given both as positional and keyword");
                    return -1;
                }
                *key_obj = value;
                key_set = 1;
            }
            else if (PyUnicode_CompareWithASCIIString(name, "padding") == 0) {
                if (nargs > 1) {
                    PyErr_SetString(PyExc_TypeError,
                        "argument 'padding' given both as positional and keyword");
                    return -1;
                }
                if (_parse_padding(value, padding) < 0)
                    return -1;
            }
            else if (PyUnicode_CompareWithASCIIString(name, "rounds") == 0) {
                if (nargs > 2) {
                    PyErr_SetString(PyExc_TypeError,
                        "argument 'rounds' given both as positional and keyword");
                    return -1;
                }
                if (_parse_rounds(value, rounds) < 0)
                    return -1;
            }
            else {
                PyErr_Format(PyExc_TypeError,
                    "'%U' is an invalid keyword argument for XXTEA()", name);
                return -1;
            }
        }
    }

    /* Positional: padding, rounds (keyword conflicts already caught above) */
    if (nargs > 1) {
        if (_parse_padding(args[1], padding) < 0)
            return -1;
    }
    if (nargs > 2) {
        if (_parse_rounds(args[2], rounds) < 0)
            return -1;
    }

    if (!*key_obj) {
        PyErr_SetString(PyExc_TypeError,
            "XXTEA() missing required argument: 'key'");
        return -1;
    }
    return 0;
}

/*
 * Apply parsed key/padding/rounds to a fresh xxtea_object.
 * Returns 0 on success, -1 on error with an exception set.
 */
static int
_apply_init_args(xxtea_object *self, PyObject *key_obj, int padding, unsigned int rounds)
{
    Py_buffer key_buf = {NULL};

    if (PyObject_GetBuffer(key_obj, &key_buf, PyBUF_SIMPLE) < 0)
        return -1;

    if (key_buf.len != 16) {
        PyErr_SetString(PyExc_ValueError, "Need a 16-byte key.");
        PyBuffer_Release(&key_buf);
        return -1;
    }

    memcpy(self->key, key_buf.buf, 16);
    self->rounds = rounds;
    self->padding = padding;
    PyBuffer_Release(&key_buf);
    return 0;
}

/*
 * Legacy tp_init fallback.  Convert the (args, kwargs) tuple/dict form into
 * the vectorcall layout and reuse _parse_init_args so there is only one copy
 * of the argument-parsing logic.
 */
static int
xxtea_object_init(xxtea_object *self, PyObject *args, PyObject *kwargs)
{
    PyObject *key_obj = NULL;
    int padding = XXTEA_PADDING_PKCS7_4_MIN8;
    unsigned int rounds = 0;

    Py_ssize_t nargs = PyTuple_GET_SIZE(args);
    Py_ssize_t nkwargs = (kwargs != NULL) ? PyDict_GET_SIZE(kwargs) : 0;

    if (nargs + nkwargs > 3) {
        PyErr_SetString(PyExc_TypeError,
            "XXTEA() takes at most 3 arguments");
        return -1;
    }

    PyObject *all_args[3] = {NULL};
    for (Py_ssize_t i = 0; i < nargs; i++) {
        all_args[i] = PyTuple_GET_ITEM(args, i);
    }

    PyObject *kwnames = NULL;
    if (nkwargs > 0) {
        kwnames = PyTuple_New(nkwargs);
        if (kwnames == NULL)
            return -1;
        Py_ssize_t pos = 0, idx = 0;
        PyObject *key, *value;
        while (PyDict_Next(kwargs, &pos, &key, &value)) {
            if (!PyUnicode_Check(key)) {
                PyErr_SetString(PyExc_TypeError, "keywords must be strings");
                Py_DECREF(kwnames);
                return -1;
            }
            Py_INCREF(key);
            PyTuple_SET_ITEM(kwnames, idx, key);
            all_args[nargs + idx] = value;
            idx++;
        }
    }

    int rc = _parse_init_args(all_args, nargs, kwnames,
                              &key_obj, &padding, &rounds);
    Py_XDECREF(kwnames);
    if (rc < 0)
        return -1;

    return _apply_init_args(self, key_obj, padding, rounds);
}

/* Vectorcall constructor for XXTEA(key, ...). */
static PyObject *
xxtea_vectorcall(PyObject *type, PyObject *const *args,
                 size_t nargsf, PyObject *kwnames)
{
    PyObject *key_obj = NULL;
    int padding = XXTEA_PADDING_PKCS7_4_MIN8;
    unsigned int rounds = 0;
    Py_ssize_t nargs = PyVectorcall_NARGS(nargsf);

    if (_parse_init_args(args, nargs, kwnames, &key_obj, &padding, &rounds) < 0)
        return NULL;

    /* Allocate a new instance via tp_alloc (not PyObject_New, because it
     * must be a heap type with the right ob_type). */
    PyObject *self = ((PyTypeObject *)type)->tp_alloc((PyTypeObject *)type, 0);
    if (self == NULL)
        return NULL;

    if (_apply_init_args((xxtea_object *)self, key_obj, padding, rounds) < 0) {
        Py_DECREF(self);
        return NULL;
    }
    return self;
}

static void
xxtea_object_dealloc(xxtea_object *self)
{
    PyTypeObject *tp = Py_TYPE(self);
    tp->tp_free((PyObject *)self);
    Py_DECREF(tp);
}

static PyObject *
xxtea_object_encrypt(xxtea_object *self, PyObject *data)
{
    return _call_object_crypt(self, data, _encrypt_impl);
}

static PyObject *
xxtea_object_decrypt(xxtea_object *self, PyObject *data)
{
    return _call_object_crypt(self, data, _decrypt_impl);
}

static PyObject *
xxtea_object_encrypt_hex(xxtea_object *self, PyObject *data)
{
    PyObject *tmp = _call_object_crypt(self, data, _encrypt_impl);
    if (!tmp)
        return NULL;

    xxtea_mod_state *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *retval = _call_one_arg(state ? state->binascii_hexlify : NULL, tmp);
    Py_DECREF(tmp);
    return retval;
}

static PyObject *
xxtea_object_decrypt_hex(xxtea_object *self, PyObject *data)
{
    xxtea_mod_state *state = PyType_GetModuleState(Py_TYPE(self));
    PyObject *tmp = _call_one_arg(state ? state->binascii_unhexlify : NULL, data);
    if (!tmp)
        return NULL;

    PyObject *retval = _call_object_crypt(self, tmp, _decrypt_impl);
    Py_DECREF(tmp);
    return retval;
}

static PyMethodDef xxtea_object_methods[] = {
    {"encrypt", (PyCFunction)xxtea_object_encrypt, METH_O,
     "encrypt(data)\n\n"
     "Encrypt data with the stored key, padding, and rounds."},
    {"decrypt", (PyCFunction)xxtea_object_decrypt, METH_O,
     "decrypt(data)\n\n"
     "Decrypt data with the stored key, padding, and rounds."},
    {"encrypt_hex", (PyCFunction)xxtea_object_encrypt_hex, METH_O,
     "encrypt_hex(data)\n\n"
     "Encrypt data and return hex-encoded bytes."},
    {"decrypt_hex", (PyCFunction)xxtea_object_decrypt_hex, METH_O,
     "decrypt_hex(data)\n\n"
     "Decrypt hex-encoded data and return original bytes."},
    {NULL, NULL, 0, NULL}
};


static PyType_Slot xxtea_type_slots[] = {
    {Py_tp_dealloc, (void *)xxtea_object_dealloc},
    {Py_tp_doc, (void *)"XXTEA(key, padding=True, rounds=0)\n\n"
                "XXTEA cipher object.  rounds=0 means auto: 6 + 52 / n, "
                "where n is the number of 32-bit words in the data.\n"
                "padding: True/Padding.PKCS7_4_MIN8 (default), Padding.PKCS7_8, "
                "Padding.LENGTH_WORD_SUFFIX, or False/None/Padding.NONE.\n"
                "Methods: encrypt(data), decrypt(data), "
                "encrypt_hex(data), decrypt_hex(data)."},
    {Py_tp_methods, xxtea_object_methods},
    {Py_tp_init, (void *)xxtea_object_init},
    {Py_tp_new, PyType_GenericNew},
    {0, NULL}
};

static PyType_Spec xxtea_type_spec = {
    .name = "xxtea.XXTEA",
    .basicsize = sizeof(xxtea_object),
    .flags = Py_TPFLAGS_DEFAULT,
    .slots = xxtea_type_slots,
};

/*****************************************************************************
 * Module Init ****************************************************************
 ****************************************************************************/

static PyObject *
_make_padding_enum(void)
{
    PyObject *enum_mod = NULL, *Enum = NULL, *members = NULL;
    PyObject *args = NULL, *kwargs = NULL, *result = NULL;

    enum_mod = PyImport_ImportModule("enum");
    if (enum_mod == NULL)
        return NULL;
    Enum = PyObject_GetAttrString(enum_mod, "Enum");
    if (Enum == NULL)
        goto done;
    members = Py_BuildValue("{s:s,s:s,s:s,s:s}",
                            "PKCS7_4_MIN8", "pkcs7_4_min8",
                            "PKCS7_8", "pkcs7_8",
                            "LENGTH_WORD_SUFFIX", "length_word_suffix",
                            "NONE", "none");
    if (members == NULL)
        goto done;
    args = Py_BuildValue("(sO)", "Padding", members);
    if (args == NULL)
        goto done;
    kwargs = Py_BuildValue("{s:O,s:s}",
                           "type", (PyObject *)&PyUnicode_Type,
                           "module", "xxtea");
    if (kwargs == NULL)
        goto done;
    result = PyObject_Call(Enum, args, kwargs);

done:
    Py_XDECREF(enum_mod);
    Py_XDECREF(Enum);
    Py_XDECREF(members);
    Py_XDECREF(args);
    Py_XDECREF(kwargs);
    return result;
}

static int
_add_padding_member(PyObject *module, PyObject *type,
                    PyObject *padding_enum, const char *name)
{
    PyObject *member = PyObject_GetAttrString(padding_enum, name);
    if (member == NULL)
        return -1;
    if (PyObject_SetAttrString(type, name, member) < 0) {
        Py_DECREF(member);
        return -1;
    }
    if (PyModule_AddObject(module, name, member) < 0) {
        Py_DECREF(member);
        return -1;
    }
    return 0;
}

static int _exec(PyObject *module)
{
    xxtea_mod_state *state = (xxtea_mod_state*)PyModule_GetState(module);
    if (state == NULL)
        return -1;

    PyObject *binascii = PyImport_ImportModule("binascii");
    if (!binascii) {
        return -1;
    }

    state->binascii_hexlify = PyObject_GetAttrString(binascii, "hexlify");
    state->binascii_unhexlify = PyObject_GetAttrString(binascii, "unhexlify");
    Py_DECREF(binascii);

    if (!state->binascii_hexlify || !state->binascii_unhexlify) {
        Py_XDECREF(state->binascii_hexlify);
        Py_XDECREF(state->binascii_unhexlify);
        state->binascii_hexlify = NULL;
        state->binascii_unhexlify = NULL;
        PyErr_SetString(PyExc_AttributeError,
            "Failed to get binascii.hexlify or binascii.unhexlify");
        return -1;
    }

    if (PyModule_AddStringConstant(module, "VERSION", VERSION) < 0)
        return -1;

    PyObject *padding_enum = _make_padding_enum();
    if (padding_enum == NULL)
        return -1;
    if (PyModule_AddObject(module, "Padding", padding_enum) < 0) {
        Py_DECREF(padding_enum);
        return -1;
    }

    PyObject *xxtea_type = PyType_FromModuleAndSpec(module, &xxtea_type_spec, NULL);
    if (xxtea_type == NULL)
        return -1;

    if (PyObject_SetAttrString(xxtea_type, "Padding", padding_enum) < 0) {
        Py_DECREF(xxtea_type);
        return -1;
    }
    if (_add_padding_member(module, xxtea_type, padding_enum, "PKCS7_4_MIN8") < 0) {
        Py_DECREF(xxtea_type);
        return -1;
    }
    if (_add_padding_member(module, xxtea_type, padding_enum, "PKCS7_8") < 0) {
        Py_DECREF(xxtea_type);
        return -1;
    }
    if (_add_padding_member(module, xxtea_type, padding_enum, "LENGTH_WORD_SUFFIX") < 0) {
        Py_DECREF(xxtea_type);
        return -1;
    }

#if PY_VERSION_HEX >= 0x03090000
    /*
     * Hook up the vectorcall constructor.  Since 3.9, PyType_Type sets its
     * tp_vectorcall_offset to the offset of tp_vectorcall within
     * PyTypeObject, so _PyVectorcall_Function reads xxtea_type->tp_vectorcall
     * directly.
     *
     * The flag is set here (not in PyType_Spec) to avoid a 3.12+
     * debug-build assertion on heap types without tp_vectorcall_offset.
     */
    ((PyTypeObject *)xxtea_type)->tp_flags |= Py_TPFLAGS_HAVE_VECTORCALL;
    ((PyTypeObject *)xxtea_type)->tp_vectorcall = xxtea_vectorcall;
#endif
#if PY_VERSION_HEX >= 0x030c0000
    /* Set after attaching Padding constants; the spec cannot include
     * IMMUTABLETYPE because that blocks SetAttr on the new heap type. */
    ((PyTypeObject *)xxtea_type)->tp_flags |= Py_TPFLAGS_IMMUTABLETYPE;
#endif

    if (PyDict_SetItemString(PyModule_GetDict(module), "XXTEA", xxtea_type) < 0) {
        Py_DECREF(xxtea_type);
        return -1;
    }
    Py_DECREF(xxtea_type);

    return 0;
}

static PyMethodDef methods[] = {
    {"encrypt", (PyCFunction)xxtea_encrypt, METH_FASTCALL | METH_KEYWORDS, xxtea_encrypt_doc},
    {"decrypt", (PyCFunction)xxtea_decrypt, METH_FASTCALL | METH_KEYWORDS, xxtea_decrypt_doc},
    {"encrypt_hex", (PyCFunction)xxtea_encrypt_hex, METH_FASTCALL | METH_KEYWORDS, xxtea_encrypt_hex_doc},
    {"decrypt_hex", (PyCFunction)xxtea_decrypt_hex, METH_FASTCALL | METH_KEYWORDS, xxtea_decrypt_hex_doc},
    {NULL, NULL, 0, NULL}
};

static PyModuleDef_Slot slots[] = {
    {Py_mod_exec, _exec},
#if PY_VERSION_HEX >= 0x030c0000
    /* Subinterpreter + per-interpreter GIL support (3.12+).
       Value 2 (PER_INTERPRETER_GIL_SUPPORTED) is required
       because value 1 (SUPPORTED, the default) means "shared
       GIL only", which _xxsubinterpreters rejects on 3.12. */
    {Py_mod_multiple_interpreters, Py_MOD_PER_INTERPRETER_GIL_SUPPORTED},
#endif
#ifdef Py_GIL_DISABLED
    {Py_mod_gil, Py_MOD_GIL_NOT_USED},
#endif
    {0, NULL}
};


static int _traverse(PyObject *module, visitproc visit, void *arg)
{
    xxtea_mod_state *state = (xxtea_mod_state*)PyModule_GetState(module);
    if (state) {
        Py_VISIT(state->binascii_hexlify);
        Py_VISIT(state->binascii_unhexlify);
    }
    return 0;
}

static int _clear(PyObject *module)
{
    xxtea_mod_state *state = (xxtea_mod_state*)PyModule_GetState(module);
    if (state) {
        Py_CLEAR(state->binascii_hexlify);
        Py_CLEAR(state->binascii_unhexlify);
    }
    return 0;
}

static void _free(void *module)
{
    _clear((PyObject *)module);
}

static struct PyModuleDef moduledef = {
    .m_base     = PyModuleDef_HEAD_INIT,
    .m_name     = "xxtea",
    .m_doc      = NULL,
    .m_size     = sizeof(struct xxtea_mod_state),
    .m_methods  = methods,
    .m_slots    = slots,
    .m_traverse = _traverse,
    .m_clear    = _clear,
    .m_free     = _free,
};

PyMODINIT_FUNC PyInit_xxtea(void)
{
    return PyModuleDef_Init(&moduledef);
}
