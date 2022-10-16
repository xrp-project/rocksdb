#ifndef _PARSER_VARINT_H_
#define _PARSER_VARINT_H_

#include <stdint.h>

#define VARINT64_SHIFT ((unsigned int) 7)
#define VARINT64_MSB ((unsigned int) (1 << (VARINT64_SHIFT))) // 128 == 0x80

int varint64_length(uint64_t n);
unsigned char *encode_varint64(unsigned char *dst, uint64_t n, uint32_t limit);
const unsigned char *decode_varint64(const unsigned char *src, uint64_t *value, uint32_t limit);

#endif // _PARSER_VARINT_H_
