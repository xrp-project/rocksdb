#ifndef _EBPF_EBPF_INTERNAL_H_
#define _EBPF_EBPF_INTERNAL_H_

#include "rocksdb_parser.h"

/*
 * Type definitions for eBPF
 */
#define uint64_t __u64
#define uint32_t __u32
#define uint8_t __u8
#define int64_t __s64
#define int32_t __s32
#define int8_t __s8
#define bool short
#define NULL (void *)0
#define true 1
#define false 0

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memset(dest, value, n) __builtin_memset((dest), (value), (n))
#define memcmp(s1, s2, n) __builtin_memcmp((s1), (s2), (n))

// Key found status
enum key_state {
    KEY_FOUND = 0x0,
    KEY_NOT_EQUAL = 0x1, // May exist elsewhere, keep searching
    KEY_NOT_FOUND = 0x2, // Does not exist in this SST file, stop searching
};

// Varint code
#define VARINT_SHIFT ((unsigned int) 7)
#define VARINT_MSB ((unsigned int) (1 << (VARINT_SHIFT))) // 128 == 0x80

// Footer member offsets
#define CHECKSUM_OFFSET 0
#define BLOCK_HANDLE_OFFSET CHECKSUM_LEN
#define LEGACY_BLOCK_HANDLE_OFFSET (MAX_FOOTER_LEN - MAGIC_NUM_LEN - 2 * MAX_BLOCK_HANDLE_LEN)
#define VERSION_OFFSET (CHECKSUM_LEN + 2 * MAX_BLOCK_HANDLE_LEN)
#define MAGIC_NUMBER_OFFSET (MAX_FOOTER_LEN - MAGIC_NUM_LEN)

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

#define kLegacyChecksumType kCRC32c

// Format version parsing
#define kLegacyFormatVersion 0
#define kLatestFormatVersion 5
#define kInvalidFormatVersion 0xffffffffU

static inline int valid_format_version(uint32_t version) {
    return version <= kLatestFormatVersion;
}

static inline int footer_bh_offset(uint32_t version) {
    return version == kLegacyFormatVersion ? LEGACY_BLOCK_HANDLE_OFFSET : BLOCK_HANDLE_OFFSET;
}

/*
 * Footer structure:
 *
 * Version 1+:
 *   Checksum: one byte
 *   Block handles (metaindex + index): kMaxEncodedLength = 2 * kMaxVarint64Length; kMaxVarint64Length = 10
 *   Version: 4 bytes
 *   Magic number: kMagicNumberLengthByte = 8
 *
 * Version 0:
 *   Block handles (metaindex + index): kMaxEncodedLength = 2 * kMaxVarint64Length; kMaxVarint64Length = 10
 *   Magic number: kMagicNumberLengthByte = 8
 *   Has default checksum value (kCRC32c)
 */
struct footer {
    uint8_t checksum;
    uint32_t version;
    struct block_handle metaindex_handle;
    struct block_handle index_handle;
    uint64_t magic_number;
};

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

// Internal key footer - contains sequence number and type packed together
#define kNumInternalBytes 8

static inline void unpack_sequence_and_type(uint64_t packed, uint64_t *seq, enum value_type *t) {
    if (seq)
        *seq = packed >> 8;

    if (t)
        *t = (enum value_type)(packed & 0xff);
}

// Key size parsing
struct key_size {
    uint32_t shared_size;
    uint32_t non_shared_size;
};

static inline uint32_t KEY_SIZE(struct key_size *key_size) {
    return key_size->shared_size + key_size->non_shared_size;
}

// Block footer parsing
#define BLOCK_FOOTER_CHECKSUM_LEN 4
#define BLOCK_FOOTER_TYPE_LEN 1
#define BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN 4
#define BLOCK_FOOTER_FIXED_LEN                         \
  (BLOCK_FOOTER_CHECKSUM_LEN + BLOCK_FOOTER_TYPE_LEN + \
   BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN)

#define BLOCK_FOOTER_RESTART_LEN 4

#define kBlockTrailerSize BLOCK_FOOTER_TYPE_LEN + BLOCK_FOOTER_CHECKSUM_LEN

#define kDataBlockIndexTypeBitShift 31

#define kMaxNumRestarts ((uint32_t)(1u << kDataBlockIndexTypeBitShift) - 1u)
#define kNumRestartsMask ((uint32_t)(1u << kDataBlockIndexTypeBitShift) - 1u)

static inline void unpack_index_type_and_num_restarts(uint32_t block_footer,
                                                      uint8_t* index_type,
                                                      uint32_t* num_restarts) {
    if (index_type) {
        if (block_footer & 1u << kDataBlockIndexTypeBitShift)
            *index_type = kDataBlockBinaryAndHash;
        else
            *index_type = kDataBlockBinarySearch;
    }

    if (num_restarts)
        *num_restarts = block_footer & kNumRestartsMask;

    // TODO: check that num_restarts <= kNumMaxRestarts
}

static inline uint64_t block_data_end(const uint32_t offset, const uint64_t size, const uint32_t num_restarts) {
    return offset + size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN - num_restarts * BLOCK_FOOTER_RESTART_LEN;
}

#endif // _EBPF_EBPF_INTERNAL_H_
