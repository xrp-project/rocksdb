#ifndef _PARSER_ROCKSDB_PARSER_H_
#define _PARSER_ROCKSDB_PARSER_H_

#include <stdint.h>

#define CHECKSUM_LEN 1
#define MAX_VARINT64_LEN 10
#define VERSION_LEN 4
#define MAGIC_NUM_LEN 8
#define MAX_BLOCK_HANDLE_LEN (2 * MAX_VARINT64_LEN)

#define FOOTER_LEN (CHECKSUM_LEN + 2 * MAX_BLOCK_HANDLE_LEN + VERSION_LEN + MAGIC_NUM_LEN)
#define LEGACY_FOOTER_LEN (2 * MAX_BLOCK_HANDLE_LEN + MAGIC_NUM_LEN)

#define BLOCK_MAGIC_NUMBER 0x88e241b785f4cff7ull // kBlockBasedTableMagicNumber
#define LEGACY_BLOCK_MAGIC_NUMBER 0xdb4775248b80fb57ull // kLegacyBlockBasedTableMagicNumber

struct rocksdb_opts {
    uint32_t magic_num_len; // kMagicNumberLengthByte = 8
    uint32_t max_varint_len; // kMaxVarint64Length = 10
    uint32_t max_block_handle_len; // kMaxEncodedLength = 2 * kMaxVarint64Length
    uint32_t footer_len; // kNewVersionsEncodedLength = 1 + 2 * BlockHandle::kMaxEncodedLength + 4 + kMagicNumberLengthByte. Version 1+
    uint64_t magic; // kBlockBasedTableMagicNumber = 0x88e241b785f4cff7ull;
};

struct block_handle {
    uint64_t offset;
    uint64_t size;
};

/*
 * Version 1+:
 *   Checksum: one byte
 *   Block handles (metaindex + index): kMaxEncodedLength = 2 * kMaxVarint64Length; kMaxVarint64Length = 10
 *   Version: 4 bytes
 *   Magic number: kMagicNumberLengthByte = 8
 */
struct footer {
    uint8_t checksum;
    uint8_t block_handles[2 * MAX_BLOCK_HANDLE_LEN];
    uint32_t version;
    uint64_t magic_number;
} __attribute__((packed));

/*
 * Version 0:
 *   Block handles (metaindex + index): kMaxEncodedLength = 2 * kMaxVarint64Length; kMaxVarint64Length = 10
 *   Magic number: kMagicNumberLengthByte = 8
 */
struct legacy_footer {
    uint8_t block_handles[2 * MAX_BLOCK_HANDLE_LEN];
    uint64_t magic_number;
} __attribute__((packed));

#endif // _PARSER_ROCKSDB_PARSER_H_
