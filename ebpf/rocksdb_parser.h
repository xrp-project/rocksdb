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

#include <linux/const.h>

#define PAGE_SIZE 4096

// Footer member sizes
#define CHECKSUM_LEN 1
#define MAX_VARINT64_LEN 10 // kMaxVarint64Length = 10
#define MAX_VARINT32_LEN 5
#define VERSION_LEN 4
#define MAGIC_NUM_LEN 8 // kMagicNumberLengthByte = 8
#define MAX_BLOCK_HANDLE_LEN (2 * MAX_VARINT64_LEN) // kMaxEncodedLength = 2 * kMaxVarint64Length

// kNewVersionsEncodedLength = 1 + 2 * BlockHandle::kMaxEncodedLength + 4 + kMagicNumberLengthByte. Version 1+
#define FOOTER_LEN (CHECKSUM_LEN + 2 * MAX_BLOCK_HANDLE_LEN + VERSION_LEN + MAGIC_NUM_LEN) // 53 bytes
#define LEGACY_FOOTER_LEN (2 * MAX_BLOCK_HANDLE_LEN + MAGIC_NUM_LEN)
#define MAX_FOOTER_LEN FOOTER_LEN // new footer > legacy footer

#define CHECKSUM_OFFSET 0
#define BLOCK_HANDLE_OFFSET CHECKSUM_LEN
#define LEGACY_BLOCK_HANDLE_OFFSET (MAX_FOOTER_LEN - MAGIC_NUM_LEN - 2 * MAX_BLOCK_HANDLE_LEN)
#define VERSION_OFFSET (CHECKSUM_LEN + 2 * MAX_BLOCK_HANDLE_LEN)
#define MAGIC_NUMBER_OFFSET (MAX_FOOTER_LEN - MAGIC_NUM_LEN)

// Magic numbers
#define BLOCK_MAGIC_NUMBER 0x88e241b785f4cff7ull // kBlockBasedTableMagicNumber
#define LEGACY_BLOCK_MAGIC_NUMBER 0xdb4775248b80fb57ull // kLegacyBlockBasedTableMagicNumber
#define NULL_BLOCK_MAGIC_NUMBER 0

#define ROCKSDB_BLOCK_SIZE 4096

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

static inline int bh_offset(uint32_t version) {
    return version == kLegacyFormatVersion ? LEGACY_BLOCK_HANDLE_OFFSET : BLOCK_HANDLE_OFFSET;
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
    uint32_t version;
    struct block_handle metaindex_handle;
    struct block_handle index_handle;
    uint64_t magic_number;
};

// eBPF program
#define MAX_KEY_LEN 63
#define MAX_VALUE_LEN 255

struct key_size {
    uint32_t shared_size;
    uint32_t non_shared_size;
};

static inline uint32_t KEY_SIZE(struct key_size *key_size) {
    return key_size->shared_size + key_size->non_shared_size;
}

enum parse_stage {
    kFooterStage = 0x0,
    kIndexStage = 0x1,
    kDataStage = 0x2
};

union varint_ctx {
    uint64_t varint64;
    uint32_t varint32;
    int64_t varsigned64;
};

struct index_parse_context {
    struct block_handle prev_data_handle;
    uint32_t index_offset;
};

struct data_parse_context {
    unsigned char value[MAX_VALUE_LEN + 1];
    uint32_t data_offset;
    enum value_type vt;
    uint64_t seq;
};

// The RocksDB context contains an array of file_context. Each file_context
// corresponds to an SST file we need to check.
// - The stage field indicates how much of the file we have already parsed
//   using the in-memory cache.
// - The fd is the file descriptor of the SST file.
// - The offset and bytes_to_read fields indicate what the next read should be.
struct file_context {
    uint32_t fd;
    enum parse_stage stage;
    uint64_t block_offset;
    uint64_t offset;
    uint64_t bytes_to_read;
};

struct file_array {
    struct file_context array[16];
    uint8_t curr_idx;
    uint8_t count;
};

struct rocksdb_ebpf_ctx {
    uint64_t block_offset; // offset of the RocksDB block in the data buffer
    enum parse_stage stage;
    int found;
    char key[MAX_KEY_LEN + 1];
    char temp_key[MAX_KEY_LEN + 1]; // used for comparisons
    struct block_handle handle; // need to set this from userspace!
    union varint_ctx varint_ctx;
    union {
        struct index_parse_context index_context;
        struct data_parse_context data_context;
    };
    struct file_array file_array;
};

#define ROUND_DOWN(x, alignment) (((x) / (alignment)) * (alignment))
#define ROUND_UP(x, alignment) __ALIGN_KERNEL((x), (alignment))

#endif // _EBPF_ROCKSDB_PARSER_H_
