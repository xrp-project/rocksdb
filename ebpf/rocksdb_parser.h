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

#define PAGE_SIZE 4096
#define EBPF_DATA_BUFFER_SIZE (1UL << 21UL)
#define EBPF_SCRATCH_BUFFER_SIZE (4096)
#define EBPF_BLOCK_SIZE 512
#define ROCKSDB_BLOCK_SIZE 4096

#define SYS_READ_XRP 445
#define SYS_READ_BPFOF 447

#define EBPF_EINVAL 22

// Footer member sizes
#define CHECKSUM_LEN 1
#define MAX_VARINT64_LEN 10 // kMaxVarint64Length = 10
#define MAX_VARINT32_LEN 5
#define VERSION_LEN 4
#define MAGIC_NUM_LEN 8 // kMagicNumberLengthByte = 8
#define MAX_BLOCK_HANDLE_LEN (2 * MAX_VARINT64_LEN) // kMaxEncodedLength = 2 * kMaxVarint64Length

// Footer sizes
// kNewVersionsEncodedLength = 1 + 2 * BlockHandle::kMaxEncodedLength + 4 + kMagicNumberLengthByte. Version 1+
#define FOOTER_LEN (CHECKSUM_LEN + 2 * MAX_BLOCK_HANDLE_LEN + VERSION_LEN + MAGIC_NUM_LEN) // 53 bytes
#define LEGACY_FOOTER_LEN (2 * MAX_BLOCK_HANDLE_LEN + MAGIC_NUM_LEN)
#define MAX_FOOTER_LEN FOOTER_LEN // new footer > legacy footer

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

struct block_handle {
    uint64_t offset;
    uint64_t size;
};

// eBPF program
#define MAX_KEY_LEN 63
#define MAX_VALUE_LEN 255

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

struct index_ctx {
    struct block_handle prev_bh;
    uint64_t offset;
};

struct data_ctx {
    unsigned char value[MAX_VALUE_LEN + 1];
    enum value_type vt;
    uint64_t offset;
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

struct rocksdb_ebpf_ctx {
    uint64_t block_offset; // offset of the RocksDB block in the data buffer
    enum parse_stage stage;
    uint8_t found;
    uint8_t curr_file_idx;
    uint8_t file_count;
    char key[MAX_KEY_LEN + 1];
    char temp_key[MAX_KEY_LEN + 1]; // used for comparisons
    struct block_handle handle; // need to set this from userspace!
    union varint_ctx varint_ctx;
    union {
        struct index_ctx index_ctx;
        struct data_ctx data_ctx;
    };
    struct file_context file_array[16];
};

// taken from <linux/const.h>
#define __ALIGN_MASK(x, mask)	(((x) + (mask)) & ~(mask))

#define ROUND_UP(x, alignment) __ALIGN_MASK(x, (typeof(x))(alignment) - 1)
#define ROUND_DOWN(x, alignment) (((x) / (alignment)) * (alignment))

#endif // _EBPF_ROCKSDB_PARSER_H_
