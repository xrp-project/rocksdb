#pragma once

#include <string>

#include <table/block_based/block_based_table_reader.h>

namespace ROCKSDB_NAMESPACE {

#define EBPF_DATA_BUFFER_SIZE (1UL << 21UL)
#define EBPF_SCRATCH_BUFFER_SIZE 4096
#define EBPF_BLOCK_SIZE 512
#define PAGE_SIZE 4096

#define SYS_READ_XRP 445

// Value types encoded as the last component of internal keys
// Incomplete list, see db/dbformat.h
enum value_type {
    kTypeDeletionXRP = 0x0,
    kTypeValueXRP = 0x1,
    kTypeMergeXRP = 0x2,
    kTypeDeletionWithTimestampXRP = 0x14,
    kTypeRangeDeletionXRP = 0xF,
    kTypeMaxValidXRP,
    kMaxValueXRP = 0x7F
};

struct block_handle {
    uint64_t offset;
    uint64_t size;
};

// TODO change to constants - write good C++
#define MAX_KEY_LEN 63
#define MAX_VALUE_LEN 255

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
    unsigned char prev_index_key[MAX_KEY_LEN + 1];
    struct block_handle prev_data_handle;
    uint32_t index_offset;
};

struct data_parse_context {
    unsigned char prev_data_key[MAX_KEY_LEN + 1];
    unsigned char value[MAX_VALUE_LEN + 1];
    uint32_t data_offset;
    enum value_type vt;
    uint64_t seq;
};

struct rocksdb_ebpf_context {
    uint64_t footer_len;
    enum parse_stage stage;
    int found;
    char key[MAX_KEY_LEN + 1];
    char temp_key[MAX_KEY_LEN + 1]; // used for comparisons
    struct block_handle handle;
    union varint_context varint_context;
    union {
        struct index_parse_context index_context;
        struct data_parse_context data_context;
    };
};

class XRPContext {
   public:
    XRPContext(const std::string &ebpf_program);
    ~XRPContext();

    Status do_xrp(const BlockBasedTable &sst, const Slice &key, Slice &value, GetContext *get_context, bool *matched);

   private:
    int load_bpf_program(const char *path);

    int bpf_fd;
    uint8_t *data_buf;
    uint8_t *scratch_buf;
    const size_t huge_page_size = 1 << 21;
};

}  // namespace ROCKSDB_NAMESPACE
