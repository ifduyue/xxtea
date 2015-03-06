/*
 * Copyright (c) 2014-2015, Yue Du
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
#include <ctype.h>
#include <stdio.h>

#define TOSTRING(x) #x
#define VALUE_TO_STRING(x) TOSTRING(x)

#ifndef Py_TYPE
#define Py_TYPE(ob) (((PyObject*)(ob))->ob_type)
#endif

#if PY_MAJOR_VERSION >= 3
#define PyString_FromStringAndSize PyBytes_FromStringAndSize
#define PyString_AS_STRING PyBytes_AsString
#endif

#define DELTA 0x9e3779b9
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))

static PyObject *module, *binascii;
static PyObject *_xxtea_pyunicode_hexlify;
static PyObject *_xxtea_pyunicode_unhexlify;
static PyObject *_xxtea_pyunicode_decrypt;


static void btea(uint32_t *v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;

    if (n > 1) {          /* Coding Part */
        rounds = 6 + 52 / n;
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
        rounds = 6 + 52 / n;
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

static int bytes2longs(const char *in, int inlen, uint32_t *out, int padding)
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

static int longs2bytes(uint32_t *in, int inlen, char *out, int padding)
{
    int i, pad;
    unsigned char *s;

    s = (unsigned char *)out;

    for (i = 0; i < inlen; i++) {
        s[4 * i] = in[i] & 0xFF;
        s[4 * i + 1] = (in[i] >> 8) & 0xFF;
        s[4 * i + 2] = (in[i] >> 16) & 0xFF;
        s[4 * i + 3] = (in[i] >> 24) & 0xFF;
    }

    i *= 4;

    /* PKCS#7 unpadding */
    if (padding) {
        pad = s[i - 1];
        i -= pad;
    }

    s[i] = '\0';

    /* How many bytes we've got */
    return i;
}

/*****************************************************************************
 * Module Functions ***********************************************************
 ****************************************************************************/

static char *keywords[] = {"data", "key", NULL};


PyDoc_STRVAR(
    xxtea_encrypt_doc,
    "encrypt (data, key)\n\n"
    "Encrypt `data` with a 16-byte `key`, return binary bytes.");

static PyObject *xxtea_encrypt(PyObject *self, PyObject *args, PyObject *kwargs)
{
    const char *data, *key;
    int alen, dlen, klen;
    PyObject *retval;
    char *retbuf;
    uint32_t *d, k[4];

    d = NULL;
    retval = NULL;
    k[0] = k[1] = k[2] = k[3] = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s#s#", keywords, &data, &dlen, &key, &klen)) {
        return NULL;
    }

    if (klen != 16) {
        PyErr_SetString(PyExc_TypeError, "Need a 16-byte key.");
        return NULL;
    }

    alen = dlen < 4 ? 2 : (dlen >> 2) + 1;
    d = (uint32_t *)calloc(alen, sizeof(uint32_t));

    if (d == NULL) {
        return PyErr_NoMemory();
    }

    bytes2longs(data, dlen, d, 1);
    bytes2longs(key, klen, k, 0);
    btea(d, alen, k);

    retval = PyString_FromStringAndSize(NULL, (alen << 2));

    if (!retval) {
        goto cleanup;
    }

    retbuf = PyString_AS_STRING(retval);
    longs2bytes(d, alen, retbuf, 0);

    free(d);

    return retval;

cleanup:

    if (d) {
        free(d);
    }

    if (retval) {
        Py_DECREF(retval);
    }

    return NULL;
}

PyDoc_STRVAR(
    xxtea_encrypt_hex_doc,
    "encrypt_hex (data, key)\n\n"
    "Encrypt `data` with a 16-byte `key`, return hex encoded bytes.");

static PyObject *xxtea_encrypt_hex(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyObject *retval, *tmp;
    retval = tmp = NULL;

    if (!(tmp = xxtea_encrypt(self, args, kwargs))) {
        return NULL;
    }

    retval = PyObject_CallMethodObjArgs(binascii, _xxtea_pyunicode_hexlify, tmp, NULL);
    Py_DECREF(tmp);

    return retval;
}

PyDoc_STRVAR(
    xxtea_decrypt_doc,
    "decrypt (data, key)\n\n"
    "Decrypt `data` with a 16-byte `key`, return original bytes.");

static PyObject *xxtea_decrypt(PyObject *self, PyObject *args, PyObject *kwargs)
{
    const char *data, *key;
    int alen, dlen, klen, rc;
    PyObject *retval;
    char *retbuf;
    uint32_t *d, k[4];

    d = NULL;
    retval = NULL;
    k[0] = k[1] = k[2] = k[3] = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s#s#", keywords, &data, &dlen, &key, &klen)) {
        return NULL;
    }

    if (klen != 16) {
        PyErr_SetString(PyExc_TypeError, "Need a 16-byte key.");
        return NULL;
    }

    retval = PyString_FromStringAndSize(NULL, dlen);

    if (!retval) {
        return NULL;
    }

    retbuf = PyString_AS_STRING(retval);

    /* not divided by 4, or length < 8 */
    if (dlen & 3 || dlen < 8) {
        PyErr_SetString(PyExc_TypeError, "Invalid data.");
        goto cleanup;
    }

    alen = dlen / 4;
    d = (uint32_t *)calloc(alen, sizeof(uint32_t));

    if (d == NULL) {
        PyErr_NoMemory();
        goto cleanup;

    }

    bytes2longs(data, dlen, d, 0);
    bytes2longs(key, klen, k, 0);
    btea(d, -alen, k);

    if ((rc = longs2bytes(d, alen, retbuf, 1)) != dlen) {
        /* Remove PKCS#7 padded chars */
        Py_SIZE(retval) = rc;
    }

    free(d);

    return retval;

cleanup:

    if (d) {
        free(d);
    }

    if (retval) {
        Py_DECREF(retval);
    }

    return NULL;
}

PyDoc_STRVAR(
    xxtea_decrypt_hex_doc,
    "decrypt_hex (data, key)\n\n"
    "Decrypt hex encoded `data` with a 16-byte `key`, return original bytes.");

static PyObject *xxtea_decrypt_hex(PyObject *self, PyObject *args, PyObject *kwargs)
{
    PyObject *data, *key, *retval, *tmp;
    data = key = retval = tmp = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "SS", keywords, &data, &key)) {
        return NULL;
    }

    if (!(tmp = PyObject_CallMethodObjArgs(binascii, _xxtea_pyunicode_unhexlify, data, NULL))) {
        return NULL;
    }

    retval = PyObject_CallMethodObjArgs(module, _xxtea_pyunicode_decrypt, tmp, key, NULL);
    Py_DECREF(tmp);

    return retval;
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

    _xxtea_pyunicode_hexlify = PyUnicode_FromString("hexlify");
    _xxtea_pyunicode_unhexlify = PyUnicode_FromString("unhexlify");
    _xxtea_pyunicode_decrypt = PyUnicode_FromString("decrypt");

    PyModule_AddStringConstant(module, "VERSION", VALUE_TO_STRING(VERSION));

#if PY_MAJOR_VERSION >= 3
    return module;
#endif
}
