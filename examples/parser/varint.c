#include <stddef.h>

#include "varint.h"

int varint_length(uint64_t n) {
    int len = 1;

    while (n >= VARINT_MSB) {
        n >>= VARINT_SHIFT;
        len++;
    }

    return len;
}

// Returns pointer to one past end of dst
unsigned char *encode_varint32(unsigned char *dst, uint32_t n, uint8_t limit) {
    unsigned char *ptr = dst;

    if (!ptr)
        return NULL;

    while (n >= VARINT_MSB) {
        *(ptr++) = (n & (VARINT_MSB - 1)) | VARINT_MSB;
        n >>= 7;
        if (ptr - dst >= limit)
            return NULL;
    }

    *(ptr++) = n;
    return ptr;
}

// Returns pointer to one past end of src
const unsigned char *decode_varint32(const unsigned char *src, uint32_t *value, uint8_t limit) {
    uint32_t result = 0;
    const unsigned char *ptr = src;

    if (!ptr || !value)
        return NULL;

    for (uint8_t shift = 0; shift <= 27 && src - ptr < limit; shift += VARINT_SHIFT) {
        unsigned char byte = *ptr;
        ptr++;

        if (byte & VARINT_MSB) {
            result |= ((byte & (VARINT_MSB - 1)) << shift);
        }
        else {
            result |= (byte << shift);
            *value = result;
            return ptr;
        }
    }

    return NULL;
}

// Returns pointer to one past end of dst
unsigned char *encode_varint64(unsigned char *dst, uint64_t n, uint8_t limit) {
    unsigned char *ptr = dst;

    if (!ptr)
        return NULL;

    while (n >= VARINT_MSB) {
        *(ptr++) = (n & (VARINT_MSB - 1)) | VARINT_MSB;
        n >>= 7;
        if (ptr - dst >= limit)
            return NULL;
    }

    *(ptr++) = n;
    return ptr;
}

// Returns pointer to one past end of src
const unsigned char *decode_varint64(const unsigned char *src, uint64_t *value, uint8_t limit) {
    uint64_t result = 0;
    const unsigned char *ptr = src;

    if (!ptr || !value)
        return NULL;

    for (uint8_t shift = 0; shift <= 63 && src - ptr < limit; shift += VARINT_SHIFT) {
        unsigned char byte = *ptr;
        ptr++;

        if (byte & VARINT_MSB) {
            result |= ((byte & (VARINT_MSB - 1)) << shift);
        }
        else {
            result |= (byte << shift);
            *value = result;
            return ptr;
        }
    }

    return NULL;
}

// Zigzag encoding and decoding for varsigned ints
uint64_t i64ToZigzag(const int64_t l) {
    return ((uint64_t)(l) << 1) ^ (uint64_t)(l >> 63);
}

int64_t zigzagToI64(uint64_t n) {
    return (n >> 1) ^ -(uint64_t)(n & 1);
}

unsigned char *encode_varsignedint64(unsigned char *dst, int64_t n, uint8_t limit) {
    return encode_varint64(dst, i64ToZigzag(n), limit);
}

const unsigned char *decode_varsignedint64(const unsigned char *src, int64_t *value, uint8_t limit) {
    uint64_t u = 0;
    const unsigned char* ret;

    if (!value)
        return NULL;
    
    ret = decode_varint64(src, &u, limit);
    *value = zigzagToI64(u);
    return ret;
}
