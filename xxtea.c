/* xxtea.c - Optimized XXTEA implementation */

#include <stdlib.h>
#include <string.h>

#define PERF_OPTIMIZE 1

// Optimized function bytes2longs with better memory handling
#ifdef PERF_OPTIMIZE
void bytes2longs(const unsigned char *src, unsigned long *dest, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        dest[i] = ((unsigned long)src[i * 4]) | ((unsigned long)src[i * 4 + 1] << 8) | ((unsigned long)src[i * 4 + 2] << 16) | ((unsigned long)src[i * 4 + 3] << 24);
    }
}
#endif

// Optimized function longs2bytes
#ifdef PERF_OPTIMIZE
void longs2bytes(const unsigned long *src, unsigned char *dest, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        dest[i * 4] = (unsigned char)(src[i] & 0xFF);
        dest[i * 4 + 1] = (unsigned char)((src[i] >> 8) & 0xFF);
        dest[i * 4 + 2] = (unsigned char)((src[i] >> 16) & 0xFF);
        dest[i * 4 + 3] = (unsigned char)((src[i] >> 24) & 0xFF);
    }
}
#endif

// Improved PKCS#7 padding validation using memcmp
#ifdef PERF_OPTIMIZE
int validate_padding(const unsigned char *data, size_t len) {
    if (len == 0) return 0;
    unsigned char pad = data[len - 1];
    size_t i;
    if (len < pad || pad > 16) return 0;
    unsigned char expected[pad];
    memset(expected, pad, pad);
    return memcmp(data + len - pad, expected, pad) == 0;
}
#endif

// Stack allocation for small buffers with hybrid malloc/stack approach
#ifdef PERF_OPTIMIZE
void process_data(const unsigned char *data, size_t length) {
    unsigned long *buffer;
    if (length < 128) { // Use stack for small buffers
        unsigned long temp[32];
        buffer = temp;
    } else { // Fallback to malloc
        buffer = (unsigned long *)malloc(length * sizeof(unsigned long));
        if (!buffer) return; // Handle malloc failure
    }
    // Further processing...
    if (length >= 128) free(buffer);
}
#endif

// Other functions and main logic...

