/*
 * Copyright (c) 2014-2020, Yue Du
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
#include <ctype.h>
#include <stdio.h>

#define VERSION "2.0.0"

#if PY_MAJOR_VERSION >= 3
#define PyString_FromStringAndSize PyBytes_FromStringAndSize
#define PyString_AS_STRING PyBytes_AsString
#endif

#define XFREE(o) do { if ((o) == NULL) ; else free(o); } while (0)

#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

static PyObject *module, *binascii;

static void btea(unsigned int *v, int n, unsigned int const key[4], unsigned int rounds)
{
    unsigned int y, z, sum;
    unsigned p, e;

    if (n > 1) {          /* Coding Part */
        rounds = rounds == 0 ? 6 + 52 / n: rounds;
        sum = 0;
        z = v[n - 1];

        do {
            sum += DELTA;
            e = (sum >> 2) & 3;

            for (p = 0; p < n - 1; p++) {
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
        rounds = rounds == 0 ? 6 + 52 / n: rounds;
        sum = rounds * DELTA;
        y = v[0];

        do {
            e = (sum >> 2) & 3;

            for (p = n - 1; p > 0; p--) {
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

static int bytes2longs(const char *in, int inlen, unsigned int *out, int padding)
{
    int i, pad;
    const unsigned char *s;

    s = (const unsigned char *)in;

    /* (i & 3) << 3 -> [0, 8, 16, 24] */
    for (i = 0; i < inlen;  i++) {
        out[i >> 2] |= s[i] << ((i & 3) << 3);
    }

    /* PKCS#7 padding */
    if (padding) {
        pad = 4 - (inlen & 3);
        /* make sure lenght of out >= 2 */
        pad = (inlen < 4) ? pad + 4 : pad;
        for (i = inlen; i < inlen + pad; i++) {
            out[i >> 2] |= pad << ((i & 3) << 3);
        }
    }

    /* Divided by 4, and then rounded up (ceil) to an integer.
     * Which is the number of how many longs we've got.
     */
    return ((i - 1) >> 2) + 1;
}

static int longs2bytes(unsigned int *in, int inlen, char *out, int padding)
{
    int i, outlen, pad;
    unsigned char *s;

    s = (unsigned char *)out;

    for (i = 0; i < inlen; i++) {
        s[4 * i] = in[i] & 0xFF;
        s[4 * i + 1] = (in[i] >> 8) & 0xFF;
        s[4 * i + 2] = (in[i] >> 16) & 0xFF;
        s[4 * i + 3] = (in[i] >> 24) & 0xFF;
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

static char *keywords[] = {"data", "key", "padding", "rounds", NULL};


PyDoc_STRVAR(
    xxtea_encrypt_doc,
    "encrypt (data, key, padding=True, rounds=0)\n\n"
    "Encrypt `data` with a 16-byte `key`, return binary bytes.");

static PyObject *xxtea_encrypt(PyObject *self, PyObject *args, PyObject *kwargs)
{
    int alen, dlen, klen, padding;
    PyObject *retval;
    char *retbuf;
    unsigned int *d, k[4], rounds;
    Py_buffer data, key;

    d = NULL;
    retval = NULL;
    k[0] = k[1] = k[2] = k[3] = 0;
    padding = 1;
    rounds = 0;
    data.buf = data.obj = key.buf = key.obj = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s*s*|iI", keywords, &data, &key, &padding, &rounds)) {
        return NULL;
    }
    padding = padding != 0 ? 1 : 0;
    dlen = data.len;
    klen = key.len;


    if (klen != 16) {
        PyErr_SetString(PyExc_ValueError, "Need a 16-byte key.");
        goto cleanup;
    }

    if (!padding && (dlen < 8 || (dlen & 3) != 0)) {
        PyErr_SetString(PyExc_ValueError, "Data length must be a multiple of 4 bytes and must not be less than 8 bytes");
        goto cleanup;
    }

    alen = dlen < 4 ? 2 : (dlen >> 2) + padding;
    d = (unsigned int *)calloc(alen, sizeof(unsigned int));

    if (d == NULL) {
        PyErr_NoMemory();
        goto cleanup;
    }

    Py_BEGIN_ALLOW_THREADS
    bytes2longs(data.buf, dlen, d, padding);
    bytes2longs(key.buf, klen, k, 0);
    btea(d, alen, k, rounds);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);

    retval = PyString_FromStringAndSize(NULL, (alen << 2));

    if (!retval) {
        goto cleanup;
    }

    retbuf = PyString_AS_STRING(retval);
    longs2bytes(d, alen, retbuf, 0);

    free(d);

    return retval;

cleanup:
    XFREE(d);
    Py_XDECREF(retval);
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    return NULL;
}

PyDoc_STRVAR(
    xxtea_encrypt_hex_doc,
    "encrypt_hex (data, key, padding=True, rounds=0)\n\n"
    "Encrypt `data` with a 16-byte `key`, return hex encoded bytes.");

static PyObject *xxtea_encrypt_hex(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyObject *retval, *tmp;
    retval = tmp = NULL;

    if (!(tmp = xxtea_encrypt(self, args, kwargs))) {
        return NULL;
    }

    retval = PyObject_CallMethod(binascii, "hexlify", "(O)", tmp, NULL);
    Py_DECREF(tmp);

    return retval;
}

PyDoc_STRVAR(
    xxtea_decrypt_doc,
    "decrypt (data, key, padding=True, rounds=0)\n\n"
    "Decrypt `data` with a 16-byte `key`, return original bytes.");

static PyObject *xxtea_decrypt(PyObject *self, PyObject *args, PyObject *kwargs)
{
    int alen, dlen, klen, rc, padding;
    PyObject *retval;
    char *retbuf;
    unsigned int *d, k[4], rounds;
    Py_buffer data, key;

    d = NULL;
    retval = NULL;
    k[0] = k[1] = k[2] = k[3] = 0;
    padding = 1;
    rounds = 0;
    data.buf = data.obj = key.buf = key.obj = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s*s*|iI", keywords, &data, &key, &padding, &rounds)) {
        return NULL;
    }
    padding = padding != 0 ? 1 : 0;
    dlen = data.len;
    klen = key.len;


    if (klen != 16) {
        PyErr_SetString(PyExc_ValueError, "Need a 16-byte key.");
        goto cleanup;
    }

    if (!padding && (dlen < 8 || dlen & 3)) {
        PyErr_SetString(PyExc_ValueError, "Data length must be a multiple of 4 bytes and must not be less than 8 bytes");
        goto cleanup;
    }

    retval = PyString_FromStringAndSize(NULL, dlen);

    if (!retval) {
        goto cleanup;
    }

    retbuf = PyString_AS_STRING(retval);

    /* not divided by 4, or length < 8 */
    if (dlen & 3 || dlen < 8) {
        PyErr_SetString(PyExc_ValueError, "Invalid data, data length is not a multiple of 4, or less than 8.");
        goto cleanup;
    }

    alen = dlen / 4;
    d = (unsigned int *)calloc(alen, sizeof(unsigned int));

    if (d == NULL) {
        PyErr_NoMemory();
        goto cleanup;

    }

    Py_BEGIN_ALLOW_THREADS
    bytes2longs(data.buf, dlen, d, 0);
    bytes2longs(key.buf, klen, k, 0);
    btea(d, -alen, k, rounds);
    rc = longs2bytes(d, alen, retbuf, padding);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);

    if (padding) {
        if (rc >= 0) {
            /* Remove PKCS#7 padded chars */
            Py_SIZE(retval) = rc;
        }
        else {
            /* Illegal PKCS#7 padding */
            PyErr_SetString(PyExc_ValueError, "Invalid data, illegal PKCS#7 padding. Could be using a wrong key.");
            goto cleanup;
        }
    }

    free(d);

    return retval;

cleanup:
    XFREE(d);
    Py_XDECREF(retval);
    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    return NULL;
}

PyDoc_STRVAR(
    xxtea_decrypt_hex_doc,
    "decrypt_hex (data, key, padding = True)\n\n"
    "Decrypt hex encoded `data` with a 16-byte `key`, return original bytes.");

static PyObject *xxtea_decrypt_hex(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyObject *data, *key, *padding, *rounds, *retval, *tmp;

    data = key = retval = tmp = NULL;
    padding = Py_BuildValue("i", 1);
    rounds = Py_BuildValue("I", 0);

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "SS|OO", keywords, &data, &key, &padding, &rounds)) {
        goto cleanup;
    }

    if (!(tmp = PyObject_CallMethod(binascii, "unhexlify", "(O)", data, NULL))) {
        goto cleanup;
    }

    retval = PyObject_CallMethod(module, "decrypt", "(OOOO)", tmp, key, padding, rounds, NULL);
    Py_DECREF(tmp);

    return retval;

cleanup:
    Py_DECREF(padding);
    Py_DECREF(rounds);
    return NULL;
}

/*****************************************************************************
 * Module Init ****************************************************************
 ****************************************************************************/

/* ref: https://docs.python.org/2/howto/cporting.html */



static PyMethodDef methods[] = {
    {"encrypt", (PyCFunction)xxtea_encrypt, METH_VARARGS | METH_KEYWORDS, xxtea_encrypt_doc},
    {"decrypt", (PyCFunction)xxtea_decrypt, METH_VARARGS | METH_KEYWORDS, xxtea_decrypt_doc},
    {"encrypt_hex", (PyCFunction)xxtea_encrypt_hex, METH_VARARGS | METH_KEYWORDS, xxtea_encrypt_hex_doc},
    {"decrypt_hex", (PyCFunction)xxtea_decrypt_hex, METH_VARARGS | METH_KEYWORDS, xxtea_decrypt_hex_doc},
    {NULL, NULL, 0, NULL}
};

#if PY_MAJOR_VERSION >= 3

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    "xxtea",
    NULL,
    -1,
    methods,
    NULL,
    NULL,
    NULL,
    NULL
};

#define INITERROR return NULL

PyObject *PyInit_xxtea(void)

#else

#define INITERROR return

void initxxtea(void)
#endif
{
#if PY_MAJOR_VERSION >= 3
    module = PyModule_Create(&moduledef);
#else
    module = Py_InitModule("xxtea", methods);
#endif

    if (module == NULL) {
        INITERROR;
    }
    if (!(binascii = PyImport_ImportModule("binascii"))) {
        Py_DECREF(module);
        INITERROR;
    }

    PyModule_AddStringConstant(module, "VERSION", VERSION);

#if PY_MAJOR_VERSION >= 3
    return module;
#endif
}

