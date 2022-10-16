#include <stddef.h>

#include "varint.h"

int varint64_length(uint64_t n) {
    int len = 1;

    while (n >= VARINT64_MSB) {
        n >>= VARINT64_SHIFT;
        len++;
    }

    return len;
}

// Returns pointer to one past end of dst
unsigned char *encode_varint64(unsigned char *dst, uint64_t n, uint32_t limit) {
    unsigned char *ptr = dst;

    if (!ptr)
        return NULL;

    while (n >= VARINT64_MSB) {
        *(ptr++) = (n & (VARINT64_MSB - 1)) | VARINT64_MSB;
        n >>= 7;
        if (ptr - dst >= limit)
            return NULL;
    }

    *(ptr++) = n;
    return ptr;
}

// Returns pointer to one past end of src
const unsigned char *decode_varint64(const unsigned char *src, uint64_t *value, uint32_t limit) {
    uint64_t result = 0;
    const unsigned char *ptr = src;

    if (!ptr || !value)
        return NULL;

    for (uint32_t shift = 0; shift <= 63 && src - ptr < limit; shift += VARINT64_SHIFT) {
        unsigned char byte = *ptr;
        ptr++;

        if (byte & VARINT64_MSB) {
            result |= ((byte & (VARINT64_MSB - 1)) << shift);
        }
        else {
            result |= (byte << shift);
            *value = result;
            return ptr;
        }
    }

    return NULL;
}
