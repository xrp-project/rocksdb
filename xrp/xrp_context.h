#pragma once

#include <string>

namespace ROCKSDB_NAMESPACE {

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
