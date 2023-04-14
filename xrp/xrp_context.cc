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

    scratch_buf = static_cast<uint8_t *>(aligned_alloc(EBPF_SCRATCH_BUFFER_SIZE, EBPF_SCRATCH_BUFFER_SIZE));
    if (!scratch_buf)
        throw std::runtime_error("aligned_alloc() failed");

    data_buf = static_cast<uint8_t *>(mmap(NULL, huge_page_size, PROT_READ | PROT_WRITE,
                                  MAP_HUGETLB | MAP_HUGE_2MB | MAP_ANON | MAP_PRIVATE, -1, 0));

    if (data_buf == MAP_FAILED)
        throw std::runtime_error("mmap() failed");

    memset(data_buf, 0, EBPF_DATA_BUFFER_SIZE);
    memset(scratch_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);
}

XRPContext::~XRPContext() {
    free(scratch_buf);
    if (munmap(data_buf, huge_page_size) != 0)
        fprintf(stdout, "XRPContext: failed to munmap %p length %lu\n", data_buf, huge_page_size);

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
    uint64_t offset, size;
    Status s = Status::OK();
    BlockHandle index_handle;

    struct rocksdb_ebpf_context *ctx = reinterpret_cast<struct rocksdb_ebpf_context *>(scratch_buf);
    const BlockBasedTable::Rep *rep = sst.get_rep();
    PosixRandomAccessFile *file = static_cast<PosixRandomAccessFile *>(rep->file->file());

    if (!file)
        s = Status::PathNotFound("sst file not found");

    if (key.size() > MAX_KEY_LEN)
        return Status::InvalidArgument();

    sst_fd = file->GetFd();
    index_handle = rep->footer.index_handle();

    offset = (index_handle.offset() / EBPF_BLOCK_SIZE) * EBPF_BLOCK_SIZE;

    memset(data_buf, 0, EBPF_DATA_BUFFER_SIZE);
    memset(scratch_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);

    ctx->footer_len = index_handle.offset() - offset;
    ctx->stage = kIndexStage;
    ctx->handle = {.offset = index_handle.offset(), .size = index_handle.size() };
    strncpy(ctx->key, key.data(), key.size()); // key.data() is not null-terminated, beware
    size = ctx->footer_len + index_handle.size() + BlockBasedTable::kBlockTrailerSize;
    size = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1); // align to PAGE_SIZE

    long ret = syscall(SYS_READ_XRP, sst_fd, data_buf, size, offset, bpf_fd, scratch_buf);

    if (ret < 0)
        s = Status::Corruption();

    if (ctx->found == 1) {
        ValueType v = static_cast<ValueType>(ctx->data_context.vt);
        ParsedInternalKey internal_key = ParsedInternalKey(key, ctx->data_context.seq, v);

        if (v == kTypeValue) {
            value.data_ = reinterpret_cast<const char *>(ctx->data_context.value);
            value.size_ = strlen(reinterpret_cast<const char *>(ctx->data_context.value));
        }
        get_context->SaveValue(internal_key, value, matched);
    }

    return s;
}

}  // namespace ROCKSDB_NAMESPACE
