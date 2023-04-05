#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <linux/mman.h>

#include <db/dbformat.h>
#include <env/io_posix.h>
#include <table/format.h>
#include <table/block_based/block_based_table_reader.h>

#include "xrp_context.h"

namespace ROCKSDB_NAMESPACE {

XRPContext::XRPContext(const std::string &ebpf_program) {
    bpf_fd = load_bpf_program(ebpf_program.c_str());

    data_buf = static_cast<uint8_t *>(aligned_alloc(EBPF_DATA_BUFFER_SIZE, EBPF_DATA_BUFFER_SIZE));
    if (!data_buf)
        throw std::runtime_error("alligned_alloc() failed");

    scratch_buf = static_cast<uint8_t *>(mmap(NULL, huge_page_size, PROT_READ | PROT_WRITE,
                                  MAP_HUGETLB | MAP_HUGE_2MB | MAP_ANON | MAP_PRIVATE, -1, 0));

    if (scratch_buf == MAP_FAILED)
        throw std::runtime_error("mmap() failed");

    memset(data_buf, 0, EBPF_DATA_BUFFER_SIZE);
    memset(scratch_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);
}

XRPContext::~XRPContext() {
    free(data_buf);
    munmap(scratch_buf, huge_page_size);
    close(bpf_fd);
}

int XRPContext::load_bpf_program(const char *path) {
    struct bpf_object *obj;
    int progfd;

    if (bpf_prog_load(path, BPF_PROG_TYPE_XRP, &obj, &progfd))
        throw std::runtime_error("bpf_prog_load() failed");

    return progfd;
}

Status XRPContext::do_xrp(const BlockBasedTable &sst, const Slice &key, Slice &value, GetContext *get_context, bool *matched) {
    int sst_fd;
    uint64_t offset;
    Status s = Status::OK();

    struct rocksdb_ebpf_context ctx = {};
    const BlockBasedTable::Rep *rep = sst.get_rep();
    PosixRandomAccessFile *file = static_cast<PosixRandomAccessFile *>(rep->file->file());

    if (!file)
        throw std::runtime_error("file does not exist");

    sst_fd = file->GetFd();

    offset = ((rep->file_size - Footer::kMaxEncodedLength) / EBPF_BLOCK_SIZE) * EBPF_BLOCK_SIZE;

    memset(data_buf, 0, EBPF_DATA_BUFFER_SIZE);
    memset(scratch_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);

    if (key.size() > MAX_KEY_LEN)
        return Status::InvalidArgument();

    ctx.footer_len = rep->file_size - offset;
    ctx.stage = kFooterStage;
    strncpy(ctx.key, key.data(), key.size());
    memcpy(scratch_buf, &ctx, sizeof(ctx));
    long ret = syscall(SYS_READ_XRP, sst_fd, data_buf, EBPF_DATA_BUFFER_SIZE, offset, bpf_fd, scratch_buf);

    ctx = *(rocksdb_ebpf_context *)scratch_buf;

    if (ret < 0)
        s = Status::Corruption();

    if (ctx.found == 1) {
        ValueType v = static_cast<ValueType>(ctx.data_context.vt);
        ParsedInternalKey internal_key = ParsedInternalKey(key, ctx.data_context.seq, v);

        if (v == kTypeValue) {
            value.data_ = reinterpret_cast<const char *>(ctx.data_context.value);
            value.size_ = strlen(reinterpret_cast<const char *>(ctx.data_context.value));
            
            get_context->SaveValue(internal_key, value, matched);
        }
    } else {
        s = Status::NotFound();
    }

    return s;
}

}  // namespace ROCKSDB_NAMESPACE
