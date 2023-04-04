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

static void die(const char *message) {
    perror(message);
    exit(1); 
}

static void __attribute__((unused)) print_block_handle(struct block_handle *handle) {
    if (handle == NULL)
        return;

    printf("Offset: %lx\n", handle->offset);
    printf("Size: %lx\n", handle->size);
}

int load_bpf_program(char *path) {
    struct bpf_object *obj;
    int ret, progfd;

    ret = bpf_prog_load(path, BPF_PROG_TYPE_XRP, &obj, &progfd);
    if (ret) {
        printf("Failed to load bpf program\n");
        exit(1);
    }

    return progfd;
}

int main(int argc, char **argv) {
    int bpf_fd, sst_fd, out_fd;
    char *filename, *key;
    uint8_t *data_buf, *scratch_buf;
    uint64_t offset;
    struct stat st;
    struct rocksdb_ebpf_context ctx;
    const size_t huge_page_size = 1 << 21;

    if (argc != 3) {
        printf("usage: ./test <sst-file> <key>\n");
        exit(1);
    }

    filename = argv[1];
    key = argv[2];

    if (strlen(key) > MAX_KEY_LEN) {
        printf("error: key is longer than 63 chars\n");
        exit(1);
    }

    bpf_fd = load_bpf_program("parser.o");

    if ((sst_fd = open(filename, O_RDONLY | O_DIRECT)) == -1)
        die("open() sst file failed");

    if (fstat(sst_fd, &st) == -1)
        die("fstat() failed");

    offset = ((st.st_size - MAX_FOOTER_LEN) / EBPF_BLOCK_SIZE) * EBPF_BLOCK_SIZE;
    // (MAX(1, (st.st_size / EBPF_BLOCK_SIZE)) - 1) * EBPF_BLOCK_SIZE;
    //offset = st.st_size - MAX_FOOTER_LEN;
    printf("footer offset (aligned to 512): %ld\n", offset);

    /*data_buf = mmap(NULL, huge_page_size, PROT_READ | PROT_WRITE, MAP_HUGETLB | MAP_HUGE_2MB | MAP_ANON, -1, 0);
    if (data_buf == MAP_FAILED)
        die("mmap() failed");*/

    if (posix_memalign((void **) &data_buf, huge_page_size, EBPF_DATA_BUFFER_SIZE) != 0)
        die("posix_memalign() failed");

    data_buf = aligned_alloc(EBPF_DATA_BUFFER_SIZE, EBPF_DATA_BUFFER_SIZE);
    if (!data_buf)
        die("aligned_alloc() failed");

    scratch_buf = mmap(NULL, huge_page_size, PROT_READ | PROT_WRITE, MAP_HUGETLB | MAP_HUGE_2MB | MAP_ANON | MAP_PRIVATE, -1, 0);
    if (scratch_buf == MAP_FAILED)
        die("mmap() failed");

    /*scratch_buf = aligned_alloc(EBPF_SCRATCH_BUFFER_SIZE, EBPF_SCRATCH_BUFFER_SIZE);
    if (!scratch_buf)
        die("aligned_alloc() failed");*/

    /*data_buf = aligned_alloc(EBPF_DATA_BUFFER_SIZE, EBPF_DATA_BUFFER_SIZE);
    if (!data_buf)
        die("aligned_alloc() failed");

    // use madvise to ask for transparent huge page
    if (posix_memalign((void **) &scratch_buf, huge_page_size, EBPF_SCRATCH_BUFFER_SIZE) != 0)
        die("posix_memalign() failed");

    if (madvise(scratch_buf, EBPF_SCRATCH_BUFFER_SIZE, MADV_HUGEPAGE) != 0)
        die("madvise(..., MADV_HUGEPAGE) failed");
*/

    memset(data_buf, 0, EBPF_DATA_BUFFER_SIZE);
    memset(scratch_buf, 0, EBPF_SCRATCH_BUFFER_SIZE);

    memset(&ctx, 0, sizeof(ctx));
    ctx.footer_len = st.st_size - offset;
    //printf("Footer len: %lu\n", ctx.footer_len);
    ctx.stage = kFooterStage;
    strncpy((char *)&ctx.key, key, strlen(key));
    memcpy(scratch_buf, &ctx, sizeof(ctx));

    long ret = syscall(SYS_READ_XRP, sst_fd, data_buf, EBPF_DATA_BUFFER_SIZE, offset, bpf_fd, scratch_buf);

    printf("Return: %ld\n", ret);
    printf("%s\n", strerror(errno));

    if (ret < 0)
        die("read_xrp() failed");

    if ((out_fd = open("outfile", O_RDWR | O_CREAT | O_TRUNC, 0666)) == -1)
        die("open() failed");

    if (write(out_fd, scratch_buf, EBPF_SCRATCH_BUFFER_SIZE) == -1)
        die("write() failed");

    ctx = *(struct rocksdb_ebpf_context *)scratch_buf;

    if (ctx.found == 1)
        printf("Value found: %s\n", ctx.data_context.value);
    else
        printf("Value not found\n");

    free(data_buf);
    //munmap(data_buf, huge_page_size);
    munmap(scratch_buf, huge_page_size);

    close(out_fd);
    close(sst_fd);
    close(bpf_fd);
}
