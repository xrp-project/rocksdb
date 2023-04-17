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

void handleCompaction(int sec) {
    const char* adapt = getenv("XRP_ADAPTIVE_RATE");
    if (adapt == nullptr) {
        return;
    }
    
    /*
    const char* old_rate = getenv("XRP_SAMPLE_RATE");

    if (old_rate == nullptr) {
        std::cerr << "XRP_SAMPLE_RATE environment variable not found." << std::endl;
        putenv((char *) "XRP_SAMPLE_RATE=10");
        return;
    }
    */

    std::cerr << "Setting sample rate to 1" << std::endl;

    putenv((char *)"XRP_SAMPLE_RATE=1");
    std::this_thread::sleep_for(std::chrono::seconds(sec));

    std::cerr << "Setting sample rate to 10" << std::endl;

    //std::string restore_rate = "XRP_SAMPLE_RATE=" + std::string(old_rate);
    putenv((char *)"XRP_SAMPLE_RATE=10");
}

XRPContext::XRPContext(const std::string &ebpf_program, const bool _is_bpfof): is_bpfof(_is_bpfof) {
    if (this->is_bpfof){
        std::cout << "XRPContext: using bpfof" << std::endl;
        this->bpf_fd = -1234;
        data_buf = static_cast<uint8_t *>(aligned_alloc(EBPF_SCRATCH_BUFFER_SIZE, EBPF_SCRATCH_BUFFER_SIZE));
        if (!data_buf)
            throw std::runtime_error("aligned_alloc() for data_buf failed");
        memset(data_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);
    }
    else {
        this->bpf_fd = load_bpf_program(ebpf_program.c_str());
        data_buf = static_cast<uint8_t *>(mmap(NULL, huge_page_size, PROT_READ | PROT_WRITE,
                                    MAP_HUGETLB | MAP_HUGE_2MB | MAP_ANON | MAP_PRIVATE, -1, 0));
        if (data_buf == MAP_FAILED)
            throw std::runtime_error("mmap() failed");
        memset(data_buf, 0, huge_page_size);
    }
    scratch_buf = static_cast<uint8_t *>(aligned_alloc(EBPF_SCRATCH_BUFFER_SIZE, EBPF_SCRATCH_BUFFER_SIZE));
    if (!scratch_buf)
        throw std::runtime_error("aligned_alloc() failed");

    memset(scratch_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);
    ctx = reinterpret_cast<struct rocksdb_ebpf_context *>(scratch_buf);
}

XRPContext::~XRPContext() {
    free(scratch_buf);
    if (this->is_bpfof)
        free(data_buf);
    else {
        if (munmap(data_buf, huge_page_size) != 0)
            fprintf(stdout, "XRPContext: failed to munmap %p length %lu\n", data_buf, huge_page_size);
        close(bpf_fd);
    }
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
    uint32_t request_size;

    if (key.size() > MAX_KEY_LEN || ctx->file_array.count == 0)
        return Status::InvalidArgument();

    strncpy(ctx->key, key.data(), key.size());

    struct file_context start_file = ctx->file_array.array[0];
    ctx->footer_len = start_file.footer_len;
    ctx->stage = start_file.stage; // TODO: change when using block cache

    ctx->handle.size = start_file.bytes_to_read;
    ctx->handle.offset = start_file.offset;
    if (ctx->stage == kDataStage) {
        request_size = ctx->handle.size + ctx->footer_len + BlockBasedTable::kBlockTrailerSize;

        request_size = (request_size + (EBPF_BLOCK_SIZE - 1)) & ~(EBPF_BLOCK_SIZE - 1);
    } else if (ctx->stage == kIndexStage) {
        request_size = ctx->handle.size;
    } else {
        request_size = 4096;
    }

    long ret = syscall(SYS_READ_XRP, start_file.fd, data_buf, request_size, start_file.offset, bpf_fd, scratch_buf);

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
    if (this->is_bpfof)
        memset(data_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);
 //   else
 //       memset(data_buf, 0, huge_page_size);

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

        size = cache_file.bytes_to_read;

        stage = kDataStage;
    } else {
        index_handle = rep->footer.index_handle();

        offset = (index_handle.offset() / EBPF_BLOCK_SIZE) * EBPF_BLOCK_SIZE;
        footer_len = index_handle.offset() - offset;

        size = footer_len + index_handle.size() + BlockBasedTable::kBlockTrailerSize;
        size = (size + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
        stage = kIndexStage;
    }

    file_ctx->fd = sst_fd;
    file_ctx->footer_len = footer_len;
    file_ctx->stage = stage;

    file_ctx->bytes_to_read = size;
    file_ctx->offset = offset;

    // print out all of the above
    /*
    std::cout << "fd: " << file_ctx->fd << std::endl;
    std::cout << "footer_len: " << file_ctx->footer_len << std::endl;
    std::cout << "stage: " << file_ctx->stage << std::endl;
    std::cout << "bytes_to_read: " << file_ctx->bytes_to_read << std::endl;
    std::cout << "offset: " << file_ctx->offset << std::endl;
*/
}

uint32_t XRPContext::GetSampleRate() {
    // random default sample rate
    uint32_t rate = 100;

    const char* sample_var = std::getenv("XRP_SAMPLE_RATE"); 
    if (sample_var != nullptr) {
        try {
            rate = std::stoi(sample_var);
        } catch (const std::invalid_argument& ex) {
            std::cerr << "Error: invalid argument for XRP_SAMPLE_RATE: " << ex.what() << std::endl;
        }
    }

    return rate;
}

}  // namespace ROCKSDB_NAMESPACE
