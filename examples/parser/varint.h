#ifndef _PARSER_VARINT_H_
#define _PARSER_VARINT_H_

#include <stdint.h>

#define VARINT_SHIFT ((unsigned int) 7)
#define VARINT_MSB ((unsigned int) (1 << (VARINT_SHIFT))) // 128 == 0x80

int varint_length(uint64_t n);

unsigned char *encode_varint32(unsigned char *dst, uint32_t n, uint8_t limit);
const unsigned char *decode_varint32(const unsigned char *src, uint32_t *value, uint8_t limit);

unsigned char *encode_varint64(unsigned char *dst, uint64_t n, uint8_t limit);
const unsigned char *decode_varint64(const unsigned char *src, uint64_t *value, uint8_t limit);

#endif // _PARSER_VARINT_H_
