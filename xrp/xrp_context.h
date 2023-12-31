#pragma once

#include <cstdint>
#include <string>
#include <atomic>

#include <ebpf/rocksdb_parser.h>
#include <table/block_based/block_based_table_reader.h>

namespace ROCKSDB_NAMESPACE {

#define EBPF_PARSER_PATH "/mydata/tal_rocksdb/ebpf/parser.o"

void handleCompaction();

class XRPContext {
   public:
    XRPContext(const std::string &ebpf_program, const bool is_bpfof);
    ~XRPContext();

    Status Get(const Slice &key, Slice &value, ParsedInternalKey *internal_key, bool *matched);
    void Reset(void);
    void AddFile(const BlockBasedTable &sst, struct file_context &input_file);
    uint32_t GetSampleRate();
    uint32_t GetFileCount();

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
