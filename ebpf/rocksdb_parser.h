#ifndef _EBPF_ROCKSDB_PARSER_H_
#define _EBPF_ROCKSDB_PARSER_H_

#ifdef ROCKSDB_EBPF
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
//#define NULL 0
#define true 1
#define false 0
#else
#include <stdint.h>
#endif

// Footer member sizes
#define CHECKSUM_LEN 1
#define MAX_VARINT64_LEN 10 // kMaxVarint64Length = 10
#define MAX_VARINT32_LEN 5
#define VERSION_LEN 4
#define MAGIC_NUM_LEN 8 // kMagicNumberLengthByte = 8
#define MAX_BLOCK_HANDLE_LEN (2 * MAX_VARINT64_LEN) // kMaxEncodedLength = 2 * kMaxVarint64Length

// kNewVersionsEncodedLength = 1 + 2 * BlockHandle::kMaxEncodedLength + 4 + kMagicNumberLengthByte. Version 1+
#define FOOTER_LEN (CHECKSUM_LEN + 2 * MAX_BLOCK_HANDLE_LEN + VERSION_LEN + MAGIC_NUM_LEN)
#define LEGACY_FOOTER_LEN (2 * MAX_BLOCK_HANDLE_LEN + MAGIC_NUM_LEN)
#define MAX_FOOTER_LEN FOOTER_LEN // new footer > legacy footer

#define MAX_VARINT32_LEN 5

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

// Value types encoded as the last component of internal keys
// Incomplete list, see db/dbformat.h
enum value_type {
    kTypeDeletion = 0x0,
    kTypeValue = 0x1,
    kTypeMerge = 0x2,
    kTypeDeletionWithTimestamp = 0x14,
    kTypeRangeDeletion = 0xF,
    kTypeMaxValid,
    kMaxValue = 0x7F
};

static inline void unpack_sequence_and_type(uint64_t packed, uint64_t *seq, enum value_type *t) {
    if (seq)
        *seq = packed >> 8;

    if (t)
        *t = (enum value_type)(packed & 0xff);
}

struct block_handle {
    uint64_t offset;
    uint64_t size;
};

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
    struct block_handle metaindex_handle;
    struct block_handle index_handle;
    uint32_t version;
    uint64_t magic_number;
};

// Metaindex block
#define kRangeDelBlockName "rocksdb.range_del"
#define kPropertiesBlockName "rocksdb.properties"
#define kPropertiesBlockOldName "rocksdb.stats"
#define kCompressionDictBlockName "rocksdb.compression_dict"

// Block Based Table Property Names - Taken from struct BlockBasedTablePropertyName
#define kIndexTypeProperty "rocksdb.block.based.table.index.type" // 4 bytes
#define kWholeKeyFilteringProperty "rocksdb.block.based.table.whole.key.filtering"
#define kPrefixFilteringProperty "rocksdb.block.based.table.prefix.filtering"

// eBPF program
#define MAX_KEY_LEN 63

enum parse_stage {
    kFooterStage = 0x0,
    kIndexStage = 0x1,
    kDataStage = 0x2
};

union varint_context {
    uint64_t varint64;
    uint32_t varint32;
    int64_t varsigned64;
};

struct index_parse_context {
    char prev_index_key[MAX_KEY_LEN + 1];
    struct block_handle prev_data_handle;
};

struct rocksdb_ebpf_context {
    uint32_t footer_len;
    char key[MAX_KEY_LEN + 1];
//    char index_key[MAX_KEY_LEN + 1];
    struct block_handle handle;
    enum parse_stage stage;
    union varint_context varint_context;
    struct index_parse_context index_context;
};

#endif // _EBPF_ROCKSDB_PARSER_H_
