#define _GNU_SOURCE     // for O_DIRECT
#define _ISOC11_SOURCE  // for aligned_alloc(), posix_memalign()
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>   // for madvise()
#include <sys/param.h>  // for MAX()
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/mman.h>

#include "ebpf.h"
#include "rocksdb_parser.h"

const size_t huge_page_size = 1UL << 21UL;

static void die(const char *message) {
    perror(message);
    exit(1); 
}

static int load_bpf_program(char *path) {
    struct bpf_object *obj;
    int ret, progfd;

    ret = bpf_prog_load(path, BPF_PROG_TYPE_XRP, &obj, &progfd);
    if (ret) {
        printf("Failed to load bpf program\n");
        exit(1);
    }

    return progfd;
}

static int buffer_setup(uint8_t **data_buf, uint8_t **scratch_buf) {
    const int mmap_flags = MAP_HUGETLB | MAP_HUGE_2MB | MAP_ANON | MAP_PRIVATE;

    // Allocate huge page for the XRP data buffer
    uint8_t *tmp_data_buf = mmap(NULL, huge_page_size, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);

    if (tmp_data_buf == MAP_FAILED) {
        perror("mmap() failed");
        return -1;
    }

    // Allocate XRP scratch buffer, aligned to page size
    if (posix_memalign((void **) scratch_buf, EBPF_SCRATCH_BUFFER_SIZE, EBPF_SCRATCH_BUFFER_SIZE) != 0) {
        perror("posix_memalign() failed");
        return -1;
    }

    *data_buf = tmp_data_buf;

    memset(*data_buf, 0, EBPF_DATA_BUFFER_SIZE);
    memset(*scratch_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);

    return 0;
}

static void buffer_release(uint8_t *data_buf, uint8_t *scratch_buf) {
    if (munmap(data_buf, EBPF_DATA_BUFFER_SIZE) != 0)
        fprintf(stderr, "failed to munmap %p length %lu\n", data_buf, EBPF_DATA_BUFFER_SIZE);

    free(scratch_buf);
}

// Returns offset into sst_fd to read from
static uint64_t context_setup(int sst_fd, char *key, struct rocksdb_ebpf_context *ctx) {
    struct stat st;
    uint64_t block_offset, footer_offset;

    if (fstat(sst_fd, &st) == -1) {
        perror("fstat() failed");
        return -1;
    }

    // Calculate the offset of the footer and the disk block it starts in
    footer_offset = st.st_size - MAX_FOOTER_LEN;
    block_offset = ROUND_DOWN(footer_offset, EBPF_BLOCK_SIZE);

    // Set up XRP context struct
    ctx->offset_in_block = footer_offset - block_offset;
    ctx->stage = kFooterStage;
    strncpy((char *)&ctx->key, key, strlen(key) + 1);

    return block_offset;
}

int main(int argc, char **argv) {
    int bpf_fd, sst_fd, out_fd;
    uint64_t offset;
    long ret;
    char *filename, *key;
    uint8_t *data_buf, *scratch_buf;
    struct rocksdb_ebpf_context *ctx;

    if (argc != 3) {
        printf("usage: ./test <sst-file> <key>\n");
        exit(1);
    }

    filename = argv[1];
    key = argv[2];

    if (strlen(key) > MAX_KEY_LEN) {
        printf("error: key is longer than %d chars\n", MAX_KEY_LEN);
        exit(1);
    }

    bpf_fd = load_bpf_program("parser.o");

    if ((sst_fd = open(filename, O_RDONLY | O_DIRECT)) == -1)
        die("open() sst file failed");

    if (buffer_setup(&data_buf, &scratch_buf) != 0)
        exit(1);

    ctx = (struct rocksdb_ebpf_context *)scratch_buf;

    if ((offset = context_setup(sst_fd, key, ctx)) < 0)
        exit(1);

    ret = syscall(SYS_READ_XRP, sst_fd, data_buf, 4096, offset, bpf_fd, scratch_buf);

    fprintf(stderr, "read_xrp() return: %ld\n", ret);
    fprintf(stderr, "%s\n", strerror(errno));

    if (ret < 0)
        die("read_xrp() failed");

    if ((out_fd = open("outfile", O_RDWR | O_CREAT | O_TRUNC, 0666)) == -1)
        die("open() failed");

    if (write(out_fd, data_buf, EBPF_DATA_BUFFER_SIZE) == -1)
        die("write() failed");

    if (ctx->found == 1)
        printf("Value found: %s\n", ctx->data_context.value);
    else
        printf("Value not found\n");

    buffer_release(data_buf, scratch_buf);

    close(out_fd);
    close(sst_fd);
    close(bpf_fd);
}
