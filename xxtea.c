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
 */


#include <Python.h>
#include <stdint.h>
#include <string.h>

#define VERSION "5.1.1.dev0"

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

static Py_ssize_t bytes2longs(const char *in, Py_ssize_t inlen, uint32_t *out, int padding)
{
    Py_ssize_t i;
    int pad;
    const unsigned char *s;

    s = (const unsigned char *)in;

    /* Fast path: process 4 bytes at a time */
    Py_ssize_t nwords = inlen >> 2;
    for (i = 0; i < nwords; i++) {
#if PY_LITTLE_ENDIAN
        memcpy(&out[i], s + 4 * i, 4);
#else
        const unsigned char *p = s + 4 * i;
        out[i] = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
#endif
    }

    /* Handle remaining 0-3 bytes */
    i = nwords << 2;
    for (; i < inlen; i++) {
        out[i >> 2] |= (uint32_t)s[i] << ((i & 3) << 3);
    }

    /* PKCS#7 padding */
    if (padding) {
        pad = 4 - (inlen & 3);
        /* make sure length of out >= 2 */
        pad = (inlen < 4) ? pad + 4 : pad;
        for (; i < inlen + pad; i++) {
            out[i >> 2] |= (uint32_t)pad << ((i & 3) << 3);
        }
    }

    /* Divided by 4, and then rounded up (ceil) to an integer.
     * Which is the number of how many longs we've got.
     */
    return ((i - 1) >> 2) + 1;
}

static Py_ssize_t longs2bytes(const uint32_t *in, Py_ssize_t inlen, char *out, int padding)
{
    Py_ssize_t i, outlen;
    int pad;
    unsigned char *s;

    s = (unsigned char *)out;

    /*
     * In-place path: used by _decrypt_impl where `out` is the same PyBytes
     * buffer that already holds the uint32_t words.
     * - Little endian: the byte representation is already correct, nothing to do.
     * - Big endian: swap each word's bytes.  Read the whole word into a local
     *   variable before writing any of its bytes, because in and s alias.
     */
    if (in == (const uint32_t *)out) {
#if PY_LITTLE_ENDIAN
        /* nothing */
#else
        for (i = 0; i < inlen; i++) {
            uint32_t word = in[i];
            s[4 * i] = (unsigned char)(word & 0xFF);
            s[4 * i + 1] = (unsigned char)((word >> 8) & 0xFF);
            s[4 * i + 2] = (unsigned char)((word >> 16) & 0xFF);
            s[4 * i + 3] = (unsigned char)((word >> 24) & 0xFF);
        }
#endif
    }
    else {
        for (i = 0; i < inlen; i++) {
#if PY_LITTLE_ENDIAN
            memcpy(s + 4 * i, &in[i], 4);
#else
            s[4 * i] = (unsigned char)(in[i] & 0xFF);
            s[4 * i + 1] = (unsigned char)((in[i] >> 8) & 0xFF);
            s[4 * i + 2] = (unsigned char)((in[i] >> 16) & 0xFF);
            s[4 * i + 3] = (unsigned char)((in[i] >> 24) & 0xFF);
#endif
        }
    }

    outlen = inlen * 4;

    /* PKCS#7 unpadding */
    if (padding) {
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

    /* How many bytes we've got */
    return outlen;
}

/*****************************************************************************
 * Module Functions ***********************************************************
 ****************************************************************************/

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
    *padding = 1;
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
                int res = PyObject_IsTrue(value);
                if (res < 0) return -1;
                *padding = res;
                padding_set = 1;
            }
            else if (PyUnicode_CompareWithASCIIString(name, "rounds") == 0) {
                if (nargs > 3) { PyErr_SetString(PyExc_TypeError,
                    "argument 'rounds' given both as positional and keyword");
                    return -1; }
                unsigned long val = PyLong_AsUnsignedLong(value);
                if (val == (unsigned long)-1 && PyErr_Occurred())
                    return -1;
                if (val > UINT_MAX) {
                    PyErr_SetString(PyExc_OverflowError,
                        "rounds value too large");
                    return -1;
                }
                *rounds = (unsigned int)val;
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
        int res = PyObject_IsTrue(args[2]);
        if (res < 0) return -1;
        *padding = res;
    }
    if (nargs > 3 && !rounds_set) {
        unsigned long val = PyLong_AsUnsignedLong(args[3]);
        if (val == (unsigned long)-1 && PyErr_Occurred())
            return -1;
        if (val > UINT_MAX) {
            PyErr_SetString(PyExc_OverflowError, "rounds value too large");
            return -1;
        }
        *rounds = (unsigned int)val;
    }

    if (!*data_obj || !*key_obj) {
        PyErr_Format(PyExc_TypeError,
            "function missing required arguments: 'data' and 'key'");
        return -1;
    }

    return 0;
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

/*
 * Internal encrypt implementation — takes raw buffers, returns PyBytes or NULL.
 */
static inline PyObject *
_encrypt_impl(const char *data_buf, Py_ssize_t data_len,
              const char *key_buf, int padding, unsigned int rounds)
{
    uint32_t *d = NULL;
    uint32_t k[4] = {0};
    PyObject *retval = NULL;

    if (!padding && (data_len < 8 || (data_len & 3) != 0)) {
        PyErr_SetString(PyExc_ValueError,
            "Data length must be a multiple of 4 bytes and must not be less than 8 bytes");
        return NULL;
    }

    Py_ssize_t alen = data_len < 4 ? 2 : (data_len >> 2) + padding;
    if (alen > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError, "data too large");
        return NULL;
    }
    d = (uint32_t *)calloc((size_t)alen, sizeof(uint32_t));

    if (d == NULL) {
        return PyErr_NoMemory();
    }

    Py_BEGIN_ALLOW_THREADS
    bytes2longs(data_buf, data_len, d, padding);
    bytes2longs(key_buf, 16, k, 0);
    btea(d, (int)alen, k, rounds);
    Py_END_ALLOW_THREADS

    retval = PyBytes_FromStringAndSize(NULL, alen << 2);

    if (!retval) {
        free(d);
        return NULL;
    }

    /*
     * longs2bytes writes little-endian bytes on big-endian hosts, so the
     * ciphertext is identical across architectures.
     */
    longs2bytes(d, alen, PyBytes_AsString(retval), 0);

    free(d);
    return retval;
}

/*
 * Internal decrypt implementation — takes raw buffers, returns PyBytes or NULL.
 */
static inline PyObject *
_decrypt_impl(const char *data_buf, Py_ssize_t data_len,
              const char *key_buf, int padding, unsigned int rounds)
{
    uint32_t *d = NULL;
    uint32_t k[4] = {0};

    if (data_len & 3 || data_len < 8) {
        PyErr_SetString(PyExc_ValueError,
            "Data length must be a multiple of 4 bytes and must not be less than 8 bytes");
        return NULL;
    }

    PyObject *retval = PyBytes_FromStringAndSize(NULL, data_len);

    if (!retval) {
        return NULL;
    }

    Py_ssize_t alen = data_len / 4;
    if (alen > INT_MAX) {
        PyErr_SetString(PyExc_OverflowError, "data too large");
        Py_DECREF(retval);
        return NULL;
    }
    d = (uint32_t *)calloc((size_t)alen, sizeof(uint32_t));

    if (d == NULL) {
        Py_DECREF(retval);
        return PyErr_NoMemory();
    }

    char *retbuf = PyBytes_AsString(retval);
    Py_ssize_t rc;
    Py_BEGIN_ALLOW_THREADS
    bytes2longs(data_buf, data_len, d, 0);
    bytes2longs(key_buf, 16, k, 0);
    btea(d, -(int)alen, k, rounds);
    rc = longs2bytes(d, alen, retbuf, padding);
    Py_END_ALLOW_THREADS

    if (padding) {
        if (rc >= 0) {
            /* Remove PKCS#7 padded chars */
            Py_SET_SIZE(retval, rc);
        }
        else {
            /* Illegal PKCS#7 padding */
            PyErr_SetString(PyExc_ValueError,
                "Invalid data, illegal PKCS#7 padding. Could be using a wrong key.");
            Py_DECREF(retval);
            retval = NULL;
        }
    }

    free(d);
    return retval;
}


PyDoc_STRVAR(
    xxtea_encrypt_doc,
    "encrypt (data, key, padding=True, rounds=0)\n\n"
    "Encrypt `data` with a 16-byte `key`, return binary bytes.");

static PyObject *
xxtea_encrypt(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    Py_buffer data = {NULL}, key = {NULL};
    PyObject *data_obj, *key_obj;
    int padding;
    unsigned int rounds;

    if (_parse_args(args, nargs, kwnames, &data_obj, &key_obj, &padding, &rounds) < 0)
        return NULL;
    if (_get_buffers(data_obj, key_obj, &data, &key) < 0)
        return NULL;

    PyObject *retval = _encrypt_impl(data.buf, data.len, key.buf, padding, rounds);
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    return retval;
}


PyDoc_STRVAR(
    xxtea_encrypt_hex_doc,
    "encrypt_hex (data, key, padding=True, rounds=0)\n\n"
    "Encrypt `data` with a 16-byte `key`, return hex encoded bytes.");

static PyObject *
xxtea_encrypt_hex(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    Py_buffer data = {NULL}, key = {NULL};
    PyObject *data_obj, *key_obj;
    int padding;
    unsigned int rounds;

    if (_parse_args(args, nargs, kwnames, &data_obj, &key_obj, &padding, &rounds) < 0)
        return NULL;
    if (_get_buffers(data_obj, key_obj, &data, &key) < 0)
        return NULL;

    PyObject *tmp = _encrypt_impl(data.buf, data.len, key.buf, padding, rounds);
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);

    if (!tmp)
        return NULL;

    xxtea_mod_state *state = (xxtea_mod_state*)PyModule_GetState(self);
    if (!state || !state->binascii_hexlify) {
        Py_DECREF(tmp);
        PyErr_SetString(PyExc_RuntimeError, "module state not available");
        return NULL;
    }
    PyObject *retval = PyObject_CallOneArg(state->binascii_hexlify, tmp);
    Py_DECREF(tmp);
    return retval;
}


PyDoc_STRVAR(
    xxtea_decrypt_doc,
    "decrypt (data, key, padding=True, rounds=0)\n\n"
    "Decrypt `data` with a 16-byte `key`, return original bytes.");

static PyObject *
xxtea_decrypt(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    Py_buffer data = {NULL}, key = {NULL};
    PyObject *data_obj, *key_obj;
    int padding;
    unsigned int rounds;

    if (_parse_args(args, nargs, kwnames, &data_obj, &key_obj, &padding, &rounds) < 0)
        return NULL;
    if (_get_buffers(data_obj, key_obj, &data, &key) < 0)
        return NULL;

    PyObject *retval = _decrypt_impl(data.buf, data.len, key.buf, padding, rounds);
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    return retval;
}


PyDoc_STRVAR(
    xxtea_decrypt_hex_doc,
    "decrypt_hex (data, key, padding=True, rounds=0)\n\n"
    "Decrypt hex encoded `data` with a 16-byte `key`, return original bytes.");

static PyObject *
xxtea_decrypt_hex(PyObject *self, PyObject *const *args, Py_ssize_t nargs, PyObject *kwnames)
{
    Py_buffer data = {NULL}, key = {NULL};
    PyObject *data_obj, *key_obj;
    int padding;
    unsigned int rounds;

    if (_parse_args(args, nargs, kwnames, &data_obj, &key_obj, &padding, &rounds) < 0)
        return NULL;

    /* Unhexlify hex string to bytes, then use shared buffer helper */
    xxtea_mod_state *state = (xxtea_mod_state*)PyModule_GetState(self);
    if (!state || !state->binascii_unhexlify) {
        PyErr_SetString(PyExc_RuntimeError, "module state not available");
        return NULL;
    }
    PyObject *tmp = PyObject_CallOneArg(state->binascii_unhexlify, data_obj);
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

static int
xxtea_object_init(xxtea_object *self, PyObject *args, PyObject *kwargs)
{
    static char *kwlist[] = {"key", "padding", "rounds", NULL};
    Py_buffer key_buf = {NULL};
    int padding = 1;
    Py_ssize_t rounds = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y*|pn", kwlist,
                                     &key_buf, &padding, &rounds))
        return -1;

    if (key_buf.len != 16) {
        PyErr_SetString(PyExc_ValueError, "Need a 16-byte key.");
        PyBuffer_Release(&key_buf);
        return -1;
    }

    if (rounds < 0 || (size_t)rounds > UINT_MAX) {
        PyErr_SetString(PyExc_OverflowError, "rounds value too large");
        PyBuffer_Release(&key_buf);
        return -1;
    }

    memcpy(self->key, key_buf.buf, 16);
    self->rounds = (unsigned int)rounds;
    self->padding = padding;
    PyBuffer_Release(&key_buf);
    return 0;
}

static void
xxtea_object_dealloc(xxtea_object *self)
{
    PyTypeObject *tp = Py_TYPE(self);
    tp->tp_free((PyObject *)self);
    Py_DECREF(tp);
}

static PyObject *
xxtea_object_encrypt(xxtea_object *self, PyObject *data_obj)
{
    Py_buffer data_buf = {NULL};

    if (PyObject_GetBuffer(data_obj, &data_buf, PyBUF_SIMPLE) < 0)
        return NULL;

    PyObject *retval = _encrypt_impl(data_buf.buf, data_buf.len,
                                      self->key, self->padding, self->rounds);
    PyBuffer_Release(&data_buf);
    return retval;
}

static PyObject *
xxtea_object_decrypt(xxtea_object *self, PyObject *data_obj)
{
    Py_buffer data_buf = {NULL};

    if (PyObject_GetBuffer(data_obj, &data_buf, PyBUF_SIMPLE) < 0)
        return NULL;

    PyObject *retval = _decrypt_impl(data_buf.buf, data_buf.len,
                                      self->key, self->padding, self->rounds);
    PyBuffer_Release(&data_buf);
    return retval;
}

static PyObject *
xxtea_object_encrypt_hex(xxtea_object *self, PyObject *data_obj)
{
    Py_buffer data_buf = {NULL};

    if (PyObject_GetBuffer(data_obj, &data_buf, PyBUF_SIMPLE) < 0)
        return NULL;

    PyObject *tmp = _encrypt_impl(data_buf.buf, data_buf.len,
                                   self->key, self->padding, self->rounds);
    PyBuffer_Release(&data_buf);
    if (!tmp)
        return NULL;

    xxtea_mod_state *state = PyType_GetModuleState(Py_TYPE(self));
    if (!state || !state->binascii_hexlify) {
        Py_DECREF(tmp);
        PyErr_SetString(PyExc_RuntimeError, "module state not available");
        return NULL;
    }
    PyObject *retval = PyObject_CallOneArg(state->binascii_hexlify, tmp);
    Py_DECREF(tmp);
    return retval;
}

static PyObject *
xxtea_object_decrypt_hex(xxtea_object *self, PyObject *data_obj)
{
    xxtea_mod_state *state = PyType_GetModuleState(Py_TYPE(self));
    if (!state || !state->binascii_unhexlify) {
        PyErr_SetString(PyExc_RuntimeError, "module state not available");
        return NULL;
    }
    PyObject *tmp = PyObject_CallOneArg(state->binascii_unhexlify, data_obj);
    if (!tmp)
        return NULL;

    Py_buffer data_buf = {NULL};
    if (PyObject_GetBuffer(tmp, &data_buf, PyBUF_SIMPLE) < 0) {
        Py_DECREF(tmp);
        return NULL;
    }

    PyObject *retval = _decrypt_impl(data_buf.buf, data_buf.len,
                                      self->key, self->padding, self->rounds);
    PyBuffer_Release(&data_buf);
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
    .flags = Py_TPFLAGS_DEFAULT
#if PY_VERSION_HEX >= 0x030c0000
           | Py_TPFLAGS_IMMUTABLETYPE
#endif
           ,
    .slots = xxtea_type_slots,
};

/*****************************************************************************
 * Module Init ****************************************************************
 ****************************************************************************/

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

    PyObject *xxtea_type = PyType_FromModuleAndSpec(module, &xxtea_type_spec, NULL);
    if (xxtea_type == NULL)
        return -1;

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
