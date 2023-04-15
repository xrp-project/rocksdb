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
    ctx = reinterpret_cast<struct rocksdb_ebpf_context *>(scratch_buf);
}

XRPContext::~XRPContext() {
    free(scratch_buf);
    munmap(data_buf, huge_page_size);
    close(bpf_fd);
}

int XRPContext::load_bpf_program(const char *path) {
    struct bpf_object *obj;
    int progfd;

    if (bpf_prog_load(path, BPF_PROG_TYPE_XRP, &obj, &progfd))
        throw std::runtime_error("bpf_prog_load() failed");

    return progfd;
}

Status XRPContext::Get(const Slice &key, Slice &value, GetContext *get_context, bool *matched) {
    Status s = Status::OK();

    if (key.size() > MAX_KEY_LEN || ctx->file_array.count == 0)
        return Status::InvalidArgument();

    strncpy(ctx->key, key.data(), key.size());

    struct file_context start_file = ctx->file_array.array[0];
    ctx->footer_len = start_file.footer_len;
    ctx->stage = start_file.stage; // TODO: change when using block cache

    ctx->handle.size = start_file.bytes_to_read;
    ctx->handle.offset = start_file.offset;

    long ret = syscall(SYS_READ_XRP, start_file.fd, data_buf, EBPF_DATA_BUFFER_SIZE, start_file.offset, bpf_fd, scratch_buf);

    if (ret < 0)
        s = Status::Corruption();

    if (ctx->found == 1) {
        ValueType v = static_cast<ValueType>(ctx->data_context.vt);
        ParsedInternalKey internal_key = ParsedInternalKey(key, ctx->data_context.seq, v);

        if (v == kTypeValue) {
            const char *ptr = reinterpret_cast<const char *>(ctx->data_context.value);
            value.data_ = ptr;
            value.size_ = strlen(ptr);
        }
        get_context->SaveValue(internal_key, value, matched);
    }

    return s;
}

void XRPContext::Reset(void) {
    memset(data_buf, 0, EBPF_DATA_BUFFER_SIZE);
    memset(scratch_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);
}

void XRPContext::AddFile(const BlockBasedTable &sst, struct file_context &cache_file) {
    const BlockBasedTable::Rep *rep = sst.get_rep();
    BlockHandle index_handle;
    uint64_t offset, size, footer_len;
    uint32_t sst_fd;
    enum parse_stage stage;

    // hack -- if we want to skip file, fd is set to -1.
    if (cache_file.fd == (uint32_t)-1) {
        return;
    }

    PosixRandomAccessFile *file = static_cast<PosixRandomAccessFile *>(rep->file->file());
    if (!file)
        throw std::runtime_error("SST file not found");
        
    sst_fd = file->GetFd();

    struct file_context *file_ctx = ctx->file_array.array + ctx->file_array.count++;

    if (cache_file.stage == kDataStage) {
        offset = (cache_file.offset / EBPF_BLOCK_SIZE) * EBPF_BLOCK_SIZE;
        footer_len = cache_file.offset - offset;

        size = footer_len + cache_file.bytes_to_read + BlockBasedTable::kBlockTrailerSize;
        size = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1); 

        stage = kDataStage;

    } else {
        index_handle = rep->footer.index_handle();

        offset = (index_handle.offset() / EBPF_BLOCK_SIZE) * EBPF_BLOCK_SIZE;
        footer_len = index_handle.offset() - offset;

        size = footer_len + index_handle.size() + BlockBasedTable::kBlockTrailerSize;
        stage = kIndexStage;
    }
    
    size = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1); 

    file_ctx->fd = sst_fd;
    file_ctx->footer_len = footer_len;
    file_ctx->stage = stage;

    file_ctx->bytes_to_read = size;
    file_ctx->offset = offset;
}

}  // namespace ROCKSDB_NAMESPACE
