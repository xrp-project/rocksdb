#pragma once

#include <string>

#include <table/block_based/block_based_table_reader.h>

namespace ROCKSDB_NAMESPACE {

#define EBPF_SCRATCH_BUFFER_SIZE 4096 // (4 * 4096)
#define EBPF_BLOCK_SIZE 512
#define PAGE_SIZE 4096

#define SYS_READ_XRP 445

#define EBPF_PARSER_PATH "/mydata/tal_rocksdb/ebpf/parser.o"

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

#define INITIAL_SCRATCH_DATA_PAGE 1

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

struct index_ctx {
    struct block_handle prev_bh;
    uint32_t index_offset;
};

struct data_ctx {
    unsigned char value[MAX_VALUE_LEN + 1];
    uint32_t offset;
    enum value_type vt;
    uint64_t seq;
};

struct rocksdb_ebpf_ctx {
    uint64_t block_offset;
    enum parse_stage stage;
    int found;
    char key[MAX_KEY_LEN + 1];
    char temp_key[MAX_KEY_LEN + 1]; // used for comparisons
    struct block_handle handle; // need to set this from userspace!
    union varint_ctx varint_ctx;
    union {
        struct index_ctx index_ctx;
        struct data_ctx data_ctx;
    };
    struct file_array file_array;
};

void handleCompaction(int sec);

class XRPContext {
   public:
    XRPContext(const std::string &ebpf_program, const bool is_bpfof);
    ~XRPContext();

    Status Get(const Slice &key, Slice &value, GetContext *get_context, bool *matched);
    void Reset(void);
    void AddFile(const BlockBasedTable &sst, struct file_context &input_file);
    uint32_t GetSampleRate();


   private:
    int load_bpf_program(const char *path);

    int bpf_fd;
    bool is_bpfof;
    uint8_t *data_buf;
    uint8_t *scratch_buf;
    const size_t huge_page_size = 1 << 21;
    struct rocksdb_ebpf_ctx *ctx;

};

}  // namespace ROCKSDB_NAMESPACE
