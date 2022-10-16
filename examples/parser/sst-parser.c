#include <fcntl.h>
#include <inttypes.h>
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
5. read metaindex + index handless

*/

struct rocksdb_opts def_opts = {
    .magic_num_len = MAGIC_NUM_LEN,
    .max_varint_len = MAX_VARINT64_LEN,
    .max_block_handle_len = MAX_BLOCK_HANDLE_LEN,
    .footer_len = FOOTER_LEN,
    .magic = 0x88e241b785f4cff7ull
};


static void die(const char *message) {
    perror(message);
    exit(1); 
}

int main(int argc, char **argv) {
    int sst_fd;
    char *filename;
    char footer[def_opts.footer_len];
    uint64_t magic_num;
    uint32_t version;

    printf("footer size: %d\n", sizeof(struct footer));

    if (argc != 2) {
        printf("usage: ./sst-parser <sst-file>\n");
        exit(1);
    }

    filename = argv[1];
    sst_fd = open(filename, O_RDONLY);

    if (sst_fd == -1)
        die("open() failed");

    if (lseek(sst_fd, -1 * (int) def_opts.footer_len, SEEK_END) == -1)
        die("lseek() failed");

    // printf("Curent offset: %ld\n", lseek(sst_fd, 0, SEEK_CUR));

    if (read(sst_fd, footer, def_opts.footer_len) != def_opts.footer_len)
        die("read() failed");

    // assuming little endian
    memcpy(&magic_num, &footer[def_opts.footer_len - def_opts.magic_num_len], def_opts.magic_num_len);
    printf("Parsed magic number: %lx\nGiven magic number: %lx\n", magic_num, def_opts.magic);

    if (magic_num != def_opts.magic) {
        fprintf(stderr, "magic numbers don't match: %lx (parsed) and %lx (given)\n", magic_num, def_opts.magic);
        exit(1);
    }

    // assuming little endian
    memcpy(&version, &footer[def_opts.footer_len - def_opts.magic_num_len - sizeof(uint32_t)], sizeof(uint32_t));
    printf("Parsed version number: %u\n", version);


}
