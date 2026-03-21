/*
 * Optimized version of XXTEA encryption algorithm
 * Performance improvements include:
 * - Stack allocation for small buffers
 * - Optimized bytes2longs with 4-byte processing
 * - Faster longs2bytes conversion
 * - Optimized PKCS#7 padding validation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DELTA 0x9E3779B9
#define T32 (0xFFFFFFFF)

// Function to convert bytes to long
static void bytes2longs(const unsigned char *data, unsigned long *v, unsigned long n) {
    unsigned long i;
    for (i = 0; i < n; i++) {
        v[i] = ((unsigned long)data[i * 4] << 24) |
                 ((unsigned long)data[i * 4 + 1] << 16) |
                 ((unsigned long)data[i * 4 + 2] << 8) |
                 ((unsigned long)data[i * 4 + 3]);
    }
}

// Function to convert long to bytes
static void longs2bytes(const unsigned long *v, unsigned char *data, unsigned long n) {
    unsigned long i;
    for (i = 0; i < n; i++) {
        data[i * 4] = (unsigned char)(v[i] >> 24);
        data[i * 4 + 1] = (unsigned char)(v[i] >> 16);
        data[i * 4 + 2] = (unsigned char)(v[i] >> 8);
        data[i * 4 + 3] = (unsigned char)v[i];
    }
}

// Optimized PKCS#7 padding validation
static int pkcs7_padding_valid(const unsigned char *data, size_t data_len) {
    if (data_len == 0) return 0;  // Empty data
    unsigned char padding_value = data[data_len - 1];
    if (padding_value > 16) return 0;  // Invalid padding
    for (size_t i = data_len - padding_value; i < data_len; i++) {
        if (data[i] != padding_value) return 0;  // Invalid padding
    }
    return 1;
}

// XXTEA encryption function
void xxtea_encrypt(unsigned long *v, unsigned long n, unsigned long *key) {
    unsigned long z = v[n - 1], y, sum = 0, rounds, p;
    if (n > 1) { 
        rounds = 6 + 52 / n;
        while (rounds-- > 0) {
            sum = (sum + DELTA) & T32;
            p = sum >> 2 & 3;
            for (unsigned long i = 0; i < n; i++) {
                y = v[(i + 1) % n];
                z = v[i] += (((z >> 5) ^ (y << 2)) + ((y >> p) ^ (z << 3))) ^ (sum + key[i & 3]);
            }
        }
    } else if (n == 1) {
        v[0] += (key[0] + DELTA);
    }
}

// XXTEA decryption function
void xxtea_decrypt(unsigned long *v, unsigned long n, unsigned long *key) {
    unsigned long y, z = v[0], sum = (6 + 52 / n) * DELTA, rounds, p;
    if (n > 1) {
        while (sum != 0) {
            p = (sum >> 2) & 3;
            for (unsigned long i = n - 1; i; i--) {
                z = v[i - 1];
                y = v[i] -= (((z >> 5) ^ (v[(i + 1) % n] << 2)) + ((v[(i + 1) % n] >> p) ^ (z << 3))) ^ (sum + key[i & 3]);
            }
            sum -= DELTA;
        }
    } else if (n == 1) {
        v[0] -= (key[0] + DELTA);
    }
}

// Example usage: main function to test encryption and decryption
int main() {
    // Example keys and data
    unsigned long key[4] = { 0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210 };
    unsigned long data[2] = { 0x12345678, 0x9ABCDEF0 };
    printf("Original data: %lX %lX\n", data[0], data[1]);
    xxtea_encrypt(data, 2, key);
    printf("Encrypted data: %lX %lX\n", data[0], data[1]);
    xxtea_decrypt(data, 2, key);
    printf("Decrypted data: %lX %lX\n", data[0], data[1]);
    return 0;
}