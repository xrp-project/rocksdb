#ifndef _PARSER_ROCKSDB_PARSER_H_
#define _PARSER_ROCKSDB_PARSER_H_

#include <stdint.h>

// Footer member sizes
#define CHECKSUM_LEN 1
#define MAX_VARINT64_LEN 10
#define VERSION_LEN 4
#define MAGIC_NUM_LEN 8
#define MAX_BLOCK_HANDLE_LEN (2 * MAX_VARINT64_LEN)

#define FOOTER_LEN (CHECKSUM_LEN + 2 * MAX_BLOCK_HANDLE_LEN + VERSION_LEN + MAGIC_NUM_LEN)
#define LEGACY_FOOTER_LEN (2 * MAX_BLOCK_HANDLE_LEN + MAGIC_NUM_LEN)

// Magic numbers
#define BLOCK_MAGIC_NUMBER 0x88e241b785f4cff7ull // kBlockBasedTableMagicNumber
#define LEGACY_BLOCK_MAGIC_NUMBER 0xdb4775248b80fb57ull // kLegacyBlockBasedTableMagicNumber
#define NULL_BLOCK_MAGIC_NUMBER 0

// Checksum parsing
enum checksum_type {
    kNoChecksum = 0x0,
    kCRC32c = 0x1,
    kxxHash = 0x2,
    kxxHash64 = 0x3,
    kXXH3 = 0x4,
};

#define kInvalidChecksumType ((1 << (8 * sizeof(enum checksum_type)) | kNoChecksum)

static inline int valid_checksum_type(uint8_t checksum_type) {
    return checksum_type >= kNoChecksum && checksum_type <= kXXH3;
}

// Format version parsing
#define kLegacyFormatVersion 0
#define kLatestFormatVersion 5
#define kInvalidFormatVersion 0xffffffffU

static inline int valid_format_version(uint32_t version) {
    return version <= kLatestFormatVersion;
}

// The index type that will be used for this table
enum index_type {
    kBinarySearch = 0x00,
    kHashSearch = 0x01,
    kTwoLevelIndexSearch = 0x02,
    kBinarySearchWithFirstKey = 0x03,
};

// The index type that will be used for the data block.
enum datablock_index_type {
    kDataBlockBinarySearch = 0,   // traditional block type
    kDataBlockBinaryAndHash = 1,  // additional hash index
};

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
