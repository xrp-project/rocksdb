#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "data_block_footer.h"
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

static void print_block_handle(struct block_handle *handle) {
    if (handle == NULL)
        return;

    printf("Offset: %lx\n", handle->offset);
    printf("Size: %lx\n", handle->size);
}

static void print_footer(struct footer *footer) {
    if (footer == NULL)
        return;

    printf("Footer:\n");
    printf("  Checksum type: %u\n", footer->checksum);
    printf("  Format version: %u\n", footer->version);
    printf("  Magic number: %lx\n", footer->magic_number);
    printf("\nMetaindex handle:\n");
    print_block_handle(&footer->metaindex_handle);
    printf("\nIndex handle:\n");
    print_block_handle(&footer->index_handle);
}

static void parse_footer(int sst_fd, struct footer *footer) {
    uint8_t footer_arr[MAX_FOOTER_LEN];
    const uint8_t *handle, *footer_iter = footer_arr;

    if (footer == NULL)
        diev("NULL footer pointer passed to parse_footer()");

    // Assuming little endian
    if (read(sst_fd, footer_arr, sizeof(footer_arr)) != sizeof(footer_arr))
        die("read() failed");

    // read magic number
    footer_iter += sizeof(footer_arr) - MAGIC_NUM_LEN;
    footer->magic_number = *(uint64_t *)footer_iter;

    if (footer->magic_number == BLOCK_MAGIC_NUMBER) {

        // read version
        footer_iter -= VERSION_LEN;
        footer->version = *(uint32_t *)footer_iter;

        if (!valid_format_version(footer->version))
            diev("Invalid format version: %u", footer->version);

        // read checksum type
        footer->checksum = *(uint8_t *)footer_arr;
        if (!valid_checksum_type(footer->checksum))
            diev("Invalid checksum type: %u", footer->checksum);

        // set pointer to start of block handles
        footer_iter = footer_arr + CHECKSUM_LEN;
    } else if (footer->magic_number == LEGACY_BLOCK_MAGIC_NUMBER) {
        footer->version = kLegacyFormatVersion;
        footer->checksum = kLegacyChecksumType;

        // set pointer to start of block handles
        footer_iter -= 2 * MAX_BLOCK_HANDLE_LEN;
    } else {
        diev("Invalid magic number: %lx\n", footer->magic_number);
    }

    handle = decode_varint64(footer_iter, &footer->metaindex_handle.offset, MAX_VARINT64_LEN);
    handle = decode_varint64(handle, &footer->metaindex_handle.size, MAX_VARINT64_LEN);
    if (!handle)
        diev("Parsing metaindex handle failed");

    handle = decode_varint64(handle, &footer->index_handle.offset, MAX_VARINT64_LEN);
    handle = decode_varint64(handle, &footer->index_handle.size, MAX_VARINT64_LEN);
    if (!handle)
        diev("Parsing index handle failed");
}

int main(int argc, char **argv) {
    int sst_fd;
    char *filename, *key;
    uint8_t *index_block, *data_block;
    const uint8_t *index_iter, *data_iter;
    struct block_handle data_block_handle;

    if (argc != 3) {
        printf("usage: ./sst-parser <sst-file> <key>\n");
        exit(1);
    }

    filename = argv[1];
    key = argv[2];

    if ((sst_fd = open(filename, O_RDONLY)) == -1)
        die("open() failed");

    if (lseek(sst_fd, -1 * MAX_FOOTER_LEN, SEEK_END) == -1)
        die("lseek() failed");

    // printf("Curent offset: %ld\n", lseek(sst_fd, 0, SEEK_CUR));

    struct footer footer;
    parse_footer(sst_fd, &footer);

    print_footer(&footer);

    /* meta index uses kDataBlockBinarySearch, delta encoding = True, value delta = False
       See block_builder.cc
       If not value delta encoded, has <shared><non_shared><value_size>, then key,
       then block handle. If key is delta-encoded (true by default), next key starts at first
       non-matching byte. Metaindex restart interval is 0
       Footer contains restarts (0), num_restarts+index_type packed, and then block trailer
       (block type + 4 byte checksum)
    */

    if (lseek(sst_fd, footer.index_handle.offset, SEEK_SET) == -1)
        die("lseek() failed");

    // Assuming index_value_is_delta_encoded, but index_block_restart_interval == 1 (default)
    // index_type = kBinarySearch and index_key_is_user_key

    if ((index_block = malloc(footer.index_handle.size)) == NULL)
        die("malloc() failed");

    index_iter = index_block;
    if (read(sst_fd, index_block, footer.index_handle.size) != footer.index_handle.size)
        die("read() failed");

    uint8_t index_type;
    uint32_t num_restarts;
    uint32_t *block_footer = (uint32_t *)(index_block + footer.index_handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN);

    unpack_index_type_and_num_restarts(*block_footer, &index_type, &num_restarts);
    printf("\nReading index block...\n");
    printf("Num restarts: %d, index type: %d\n", num_restarts, index_type);
    uint32_t index_end = footer.index_handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN - num_restarts * 4;

    uint8_t found = 0;

    while (index_iter < index_block + index_end) {
        uint32_t shared_size, non_shared_size;
        const unsigned char *data_key;
        index_iter = decode_varint32(index_iter, &shared_size, MAX_VARINT64_LEN);
        index_iter = decode_varint32(index_iter, &non_shared_size, MAX_VARINT64_LEN);
        if (!index_iter)
            diev("Parsing index kv failed");

        if (shared_size != 0)
            diev("Index block restart interval != 1 not supported");

        data_key = index_iter;
        index_iter += non_shared_size;

        index_iter = decode_varint64(index_iter, &data_block_handle.offset, MAX_VARINT64_LEN);
        index_iter = decode_varint64(index_iter, &data_block_handle.size, MAX_VARINT64_LEN);
        if (!index_iter)
            diev("Parsing index kv failed");

        // key > data block key, key is not in data block
        if (strncmp(key, (const char *)data_key, shared_size + non_shared_size) > 0)
            continue;

        found = 1;
        break;
    }

    if (found == 0)
        diev("Data block for key not found");

    printf("Data block for key %s: Offset: %lx Size: %lx\n", key, data_block_handle.offset, data_block_handle.size);

    free(index_block);

    if (lseek(sst_fd, data_block_handle.offset, SEEK_SET) == -1)
        die("lseek() failed");

    // Parse data block - keys delta encoded
    if ((data_block = malloc(data_block_handle.size)) == NULL)
        die("malloc() failed");

    data_iter = data_block;
    if (read(sst_fd, data_block, data_block_handle.size) != data_block_handle.size)
        die("read() failed");

    block_footer = (uint32_t *)(data_block + data_block_handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN);

    unpack_index_type_and_num_restarts(*block_footer, &index_type, &num_restarts);
    printf("\nReading data block...\n");
    printf("Num restarts: %d, index type: %d\n", num_restarts, index_type);
    uint32_t data_end = data_block_handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN - num_restarts * 4;

    found = 0;

    char *prev_data_key = NULL, *data_key, *value = NULL;

    while (data_iter < data_block + data_end) {
        uint32_t shared_size, non_shared_size, value_length;

        data_iter = decode_varint32(data_iter, &shared_size, MAX_VARINT32_LEN);
        data_iter = decode_varint32(data_iter, &non_shared_size, MAX_VARINT32_LEN);
        data_iter = decode_varint32(data_iter, &value_length, MAX_VARINT32_LEN);
        if (!data_iter)
            diev("Parsing data kv failed");

        // Remove internal footer from key
        non_shared_size -= kNumInternalBytes;

        if ((data_key = malloc(shared_size + non_shared_size + 1)) == NULL)
            die("malloc() failed");

        if (shared_size != 0) {
            if (prev_data_key == NULL)
                die("Fatal parsing error");

            memcpy(data_key, prev_data_key, shared_size);
        }

        free(prev_data_key);
        memcpy(data_key + shared_size, data_iter, non_shared_size);
        data_key[shared_size + non_shared_size] = '\0';

        prev_data_key = data_key;
        data_iter += non_shared_size;

        // key != data key, move on
        if (strncmp(key, (const char *)data_key, shared_size + non_shared_size) != 0) {
            data_iter += kNumInternalBytes + value_length;
            continue;
        }

        uint64_t packed_type_seq = *(uint64_t *)data_iter;
        uint64_t seq;
        int8_t vt;

        unpack_sequence_and_type(packed_type_seq, &seq, &vt);
        printf("Seq: %lu, type: %d\n", seq, vt);

        data_iter += kNumInternalBytes;

        if (vt != kTypeValue) {
            found = 1;
            printf("Key exists, but is no longer valid. State: %x\n", vt);
            goto cleanup;
        }

        if ((value = malloc(value_length + 1)) == NULL)
            die("malloc() failed");

        memcpy(value, data_iter, value_length);
        value[value_length] = '\0';

        found = 1;
        break;
    }

    if (found == 0)
        printf("Key %s not found.\n", key);
    else
        printf("Key found! %s, %s\n", key, value);

cleanup:

    free(prev_data_key);
    free(value);
    free(data_block);

    close(sst_fd);
}
