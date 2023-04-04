#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/mman.h>

#include <db/dbformat.h>
#include <env/io_posix.h>
#include <table/format.h>
#include <table/block_based/block_based_table_reader.h>

#include "xrp_context.h"

namespace ROCKSDB_NAMESPACE {

XRPContext::XRPContext(const std::string &ebpf_program) {
    std::cout << "Creating XRPContext" << std::endl;
    bpf_fd = load_bpf_program(ebpf_program.c_str());

    std::cout << "load_bpf_program: " << strerror(errno) << std::endl;

    if (posix_memalign((void **)&data_buf, huge_page_size, EBPF_DATA_BUFFER_SIZE) != 0)
        throw std::runtime_error("posix_memalign() failed");

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
    std::cout << "Destroying XRPContext" << std::endl;
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

    struct rocksdb_ebpf_context *ctx = reinterpret_cast<struct rocksdb_ebpf_context *>(scratch_buf);
    const BlockBasedTable::Rep *rep = sst.get_rep();
    PosixRandomAccessFile *file = static_cast<PosixRandomAccessFile *>(rep->file->file());

    if (!file)
        throw std::runtime_error("file does not exist");

    sst_fd = file->GetFd();

    std::cout << "fd = " << sst_fd << std::endl;
    offset = ((rep->file_size - Footer::kMaxEncodedLength) / EBPF_BLOCK_SIZE) * EBPF_BLOCK_SIZE;

    std::cout << "footer offset (aligned to 512): " << offset << std::endl;

    memset(data_buf, 0, EBPF_DATA_BUFFER_SIZE);
    memset(scratch_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);

    if (key.size() > MAX_KEY_LEN)
        return Status::InvalidArgument();

    ctx->footer_len = rep->file_size - offset;
    ctx->stage = kFooterStage;
    strncpy(ctx->key, key.data(), key.size());

    std::cout << "key = " << ctx->key << std::endl;
    std::cout << "key size = " << key.size() << std::endl;

    long ret = syscall(SYS_READ_XRP, sst_fd, data_buf, EBPF_DATA_BUFFER_SIZE, offset, bpf_fd, scratch_buf);
    std::cout << "ret = " << ret << std::endl;
    std::cout << "read_xrp: " << strerror(errno) << std::endl;

    if (ret < 0)
        s = Status::Corruption();

    if (ctx->found == 1) {
        std::cout << "val = " << ctx->data_context.value << std::endl;
        ValueType v = static_cast<ValueType>(ctx->data_context.vt);
        ParsedInternalKey internal_key = ParsedInternalKey(key, ctx->data_context.seq, v);

        if (v == kTypeValue) {
            value.data_ = reinterpret_cast<const char *>(ctx->data_context.value);
            value.size_ = strlen(reinterpret_cast<const char *>(ctx->data_context.value));
            
            get_context->SaveValue(internal_key, value, matched);
        }
    } else {
        s = Status::NotFound();
    }

    return s;
}

}  // namespace ROCKSDB_NAMESPACE
