#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "rocksdb_parser.h"
#include "varint.h"

/*
1. open file + get file size
2. seek to footer start
3. read magic number
4. check format version
5. check checksum type
6. read metaindex + index handles
*/

struct rocksdb_opts def_opts = {
    .magic_num_len = MAGIC_NUM_LEN,
    .max_varint_len = MAX_VARINT64_LEN,
    .max_block_handle_len = MAX_BLOCK_HANDLE_LEN,
    .footer_len = FOOTER_LEN,
    .magic = BLOCK_MAGIC_NUMBER,
};

static void die(const char *message) {
    perror(message);
    exit(1); 
}

static void diev(const char *fmt, ...) {
	va_list argp;
	va_start(argp, fmt);
	vfprintf(stderr, fmt, argp);
	va_end(argp);
	fputc('\n', stderr);
	exit(1);
}

static void print_footer(struct footer *footer) {
    if (footer == NULL)
        return;

    printf("Checksum type: %u\n", footer->checksum);
    printf("Format version: %u\n", footer->version);
    printf("Magic number: %lx\n", footer->magic_number);
}

static void print_block_handle(struct block_handle *handle) {
    if (handle == NULL)
        return;

    printf("Offset: %lx\n", handle->offset);
    printf("Size: %lx\n", handle->size);
}

int main(int argc, char **argv) {
    int sst_fd;
    char *filename;
    struct footer footer;
    struct block_handle metaindex, index;
    const uint8_t *handle;

    // printf("footer size: %ld\n", sizeof(struct footer));

    if (argc != 2) {
        printf("usage: ./sst-parser <sst-file>\n");
        exit(1);
    }

    filename = argv[1];
    sst_fd = open(filename, O_RDONLY);

    if (sst_fd == -1)
        die("open() failed");

    if (lseek(sst_fd, -1 * sizeof(struct footer), SEEK_END) == -1)
        die("lseek() failed");

    // printf("Curent offset: %ld\n", lseek(sst_fd, 0, SEEK_CUR));

    // Assuming little endian and non-legacy format
    // TODO: Cross-format parsing - first read magic number, then parse
    if (read(sst_fd, &footer, sizeof(footer)) != sizeof(footer))
        die("read() failed");

    if (footer.magic_number != def_opts.magic)
        diev("Magic numbers don't match: %lx (parsed) and %lx (given)", footer.magic_number, def_opts.magic);

    // Assuming non-legacy format
    if (!valid_format_version(footer.version) && footer.version != kLegacyFormatVersion)
        diev("Invalid format version: %u", footer.version);

    if (!valid_checksum_type(footer.checksum))
        diev("Invalid checksum type: %u", footer.checksum);

    handle = decode_varint64(footer.block_handles, &metaindex.offset, MAX_VARINT64_LEN);
    handle = decode_varint64(handle, &metaindex.size, MAX_VARINT64_LEN);
    if (!handle)
        diev("Parsing metaindex handle failed");

    handle = decode_varint64(handle, &index.offset, MAX_VARINT64_LEN);
    handle = decode_varint64(handle, &index.size, MAX_VARINT64_LEN);
    if (!handle)
        diev("Parsing index handle failed");

    printf("Footer:\n");
    print_footer(&footer);
    printf("\nMetaindex handle:\n");
    print_block_handle(&metaindex);
    printf("\nIndex handle:\n");
    print_block_handle(&index);

}
