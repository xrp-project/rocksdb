#include <linux/bpf.h>
#include <linux/const.h>
#include <bpf/bpf_helpers.h>

#include "data_block_footer.h"
#include "rocksdb_parser.h"
#include "ebpf.h"

char LICENSE[] SEC("license") = "GPL";

#define __inline inline __attribute__((always_inline))
#define __noinline __attribute__((noinline))
#define __nooptimize __attribute__((optnone))

#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memset(dest, value, n) __builtin_memset((dest), (value), (n))
#define memcmp(s1, s2, n) __builtin_memcmp((s1), (s2), (n))

/*
 * Type definitions for eBPF
 */
#define uint64_t __u64
#define uint32_t __u32
#define uint8_t __u8
#define int64_t __s64
#define int32_t __s32
#define int8_t __s8
#define bool short
#define NULL (void *)0
#define true 1
#define false 0

// Varint code
#define VARINT_SHIFT ((unsigned int) 7)
#define VARINT_MSB ((unsigned int) (1 << (VARINT_SHIFT))) // 128 == 0x80

/*
 * Decodes a variable length 64-bit unsigned integer (varint64), reading
 * from context->data + offset.
 * Returns number of bytes read, or 0 on error.
 * 
 * Encoding: https://protobuf.dev/programming-guides/encoding/#varints
 */
__noinline uint32_t decode_varint64(struct bpf_xrp *context, const uint64_t offset) {
    const uint8_t *data_buffer = context->data;
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;
    uint64_t result = 0;
    uint32_t counter = 0;

    if (offset < 0 || offset > EBPF_DATA_BUFFER_SIZE - MAX_VARINT64_LEN)
        return 0;

    for (uint8_t shift = 0; shift <= 63; shift += VARINT_SHIFT) {
        uint8_t byte = *(data_buffer + offset + counter);
        counter++;

        if (byte & VARINT_MSB) {
            result |= ((byte & (VARINT_MSB - 1)) << shift);
        }
        else {
            result |= (byte << shift);
            rocksdb_ctx->varint_ctx.varint64 = result;
            return counter;
        }
    }

    return 0;
}

/*
 * Decodes a variable length 32-bit unsigned integer (varint64), reading
 * from context->data + offset.
 * Returns number of bytes read, or 0 on error.
 * 
 * Encoding: https://protobuf.dev/programming-guides/encoding/#varints
 */
__noinline uint32_t decode_varint32(struct bpf_xrp *context, const uint64_t offset) {
    const uint8_t *data_buffer = context->data;
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;
    uint32_t result = 0, counter = 0;

    if (offset < 0 || offset > EBPF_DATA_BUFFER_SIZE - MAX_VARINT32_LEN)
        return 0;

    for (uint8_t shift = 0; shift <= 27; shift += VARINT_SHIFT) {
        uint8_t byte = *(data_buffer + offset + counter);
        counter++;

        if (byte & VARINT_MSB) {
            result |= ((byte & (VARINT_MSB - 1)) << shift);
        }
        else {
            result |= (byte << shift);
            rocksdb_ctx->varint_ctx.varint32 = result;
            return counter;
        }
    }

    return 0;
}

// https://lemire.me/blog/2022/11/25/making-all-your-integers-positive-with-zigzag-encoding/
__inline int64_t zigzagToI64(uint64_t n) {
    return (n >> 1) ^ -(uint64_t)(n & 1);
}

/*
 * Decodes a variable length 64-bit signed integer (varsignedint64), reading
 * from context->data + offset.
 * Returns number of bytes read, or 0 on error.
 * 
 * Encoding: https://protobuf.dev/programming-guides/encoding/#signed-ints
 */
__noinline uint32_t decode_varsignedint64(struct bpf_xrp *context, const uint64_t offset) {
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;
    uint32_t ret;

    ret = decode_varint64(context, offset);
    rocksdb_ctx->varint_ctx.varsigned64 = zigzagToI64(rocksdb_ctx->varint_ctx.varint64);
    return ret;
}

/* 
 * Equivalent to strncmp(rocksdb_ctx->key, rocksdb_ctx->temp_key, MAX_KEY_LEN)
 */
__noinline int strncmp_key(struct bpf_xrp *context) {
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;
    uint8_t *user_key = rocksdb_ctx->key, *block_key = rocksdb_ctx->temp_key, n = MAX_KEY_LEN;

    if (n > MAX_KEY_LEN + 1)
        return -1; // should never happen since n = MAX_KEY_LEN

    while (n && *user_key && (*user_key == *block_key)) {
        ++user_key;
        ++block_key;
        --n;
    }

    if (n == 0)
        return 0;

    return *user_key - *block_key;
}

/*
 * Reads a block handle from context->data + offset into bh.
 * Returns number of bytes read, or 0 on error.
 * 
 * A block handle is composed of the following:
 *     offset (varint64), size (varint64)
 */
__inline uint32_t read_block_handle(struct bpf_xrp *context, struct block_handle *bh, uint64_t offset) {
    uint32_t varint_delta, varint_ret;
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;

    varint_ret = decode_varint64(context, offset);
    if (varint_ret == 0)
        return 0;

    varint_delta = varint_ret;
    bh->offset = rocksdb_ctx->varint_ctx.varint64;

    varint_ret = decode_varint64(context, offset + varint_delta);
    if (varint_ret == 0)
        return 0;

    varint_delta += varint_ret;
    bh->size = rocksdb_ctx->varint_ctx.varint64;

    return varint_delta;
}

/*
 * Reads a key's sizes from context->data + offset into sizes.
 * Returns number of bytes read, or 0 on error.
 * 
 * A key's size is composed of the following:
 *     shared_size (varint32), non_shared_size (varint32)
 * 
 * The total length of the key is shared_size + non_shared_size, with
 * shared_size bytes taken from the previous key, and non_shared_size bytes
 * taken from the bytes immediately following non_shared_size in the buffer.
 */
__inline uint32_t read_key_sizes(struct bpf_xrp *context, struct key_size *sizes, uint64_t offset) {
    uint32_t varint_ret, varint_delta;
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;

    if ((varint_ret = decode_varint32(context, offset)) == 0)
        return 0;

    varint_delta = varint_ret;
    sizes->shared_size = rocksdb_ctx->varint_ctx.varint32;

    if ((varint_ret = decode_varint32(context, offset + varint_delta)) == 0)
        return 0;

    varint_delta += varint_ret;
    sizes->non_shared_size = rocksdb_ctx->varint_ctx.varint32;

    return varint_delta;
}

/*
 * Reads key sizes from context->data + offset into rocksdb_ctx->temp_key.
 * Returns 0 on success, or -1 on failure.
 * 
 * Reads non_shared_size bytes from the data buffer. rocksdb_ctx->temp_key
 * should contain the shared bytes (if they exist).
 */
__noinline int read_key(struct bpf_xrp *context, struct key_size *sizes, uint64_t offset) {
    /* TODO investigate why passing in a pointer with func-by-func verification works */
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;
    uint8_t *key = rocksdb_ctx->temp_key;
    uint8_t *block = context->data;

    if (sizes == NULL)
        return -1;

    if (KEY_SIZE(sizes) > MAX_KEY_LEN)
        return -1;

    if (offset > EBPF_DATA_BUFFER_SIZE - sizes->non_shared_size)
        return -1;

    /*
     * Copy the non-shared component of the key from the data buffer starting at
     * key + shared_size.
     * 
     * If there is no shared component, shared_size will be 0 and this will copy
     * the entire key. Otherwise, the shared component will be stored in the key
     * from the previous iteration.
     */
    for (int i = 0; i < (sizes->non_shared_size & MAX_KEY_LEN); i++)
        key[(sizes->shared_size + i) & MAX_KEY_LEN] = block[(offset + i) & (EBPF_DATA_BUFFER_SIZE - 1)];

    // Null-terminate the key
    key[KEY_SIZE(sizes) & MAX_KEY_LEN] = '\0';

    return 0;
}

/*
 * Reads a block footer from context->data + offset into block_footer.
 * Calculates the end of the block from rocksdb_ctx->handle.
 *
 * Returns 0 on success, or -1 on failure.
 */
__inline int read_block_footer(struct bpf_xrp *context, const uint64_t offset, uint8_t* index_type, uint32_t* num_restarts) {
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;
    uint32_t block_footer;
    uint64_t block_end_offset;

    block_end_offset = offset + rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN;

    if (block_end_offset > EBPF_DATA_BUFFER_SIZE - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN || rocksdb_ctx->handle.size < BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN)
        return -1;

    block_footer = *(uint32_t *)(context->data + block_end_offset);

    /*
     * The block footer contains 4 bytes right before the restart ranges
     * containing the index type and the number of restart entries packed
     * together.
     */
    unpack_index_type_and_num_restarts(block_footer, index_type, num_restarts);

    return 0;
}

/*
 * Set up the eBPF context struct for the next call.
 * bh points to the desired block handle to read from in the next call.
 */
__inline void prep_next_stage(struct bpf_xrp *context, struct block_handle *bh, enum parse_stage stage) {
    uint64_t block_size;
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;

    rocksdb_ctx->handle = *bh;

    /*
     * XRP can only read from addresses that are aligned to EBPF_BLOCK_SIZE.
     * Set the address to the disk block containing the desired offset, and
     * store the number of bytes between the disk block start and the offset.
     */
    context->next_addr[0] = ROUND_DOWN(bh->offset, EBPF_BLOCK_SIZE);
    rocksdb_ctx->block_offset = bh->offset - context->next_addr[0];

    /*
     * XRP can only read sizes that are multiples of a disk block.
     * Also account for the bytes between the start of the block and the offset,
     * and the block trailer (which isn't accounted for in the block handle).
     */
    block_size = rocksdb_ctx->block_offset + bh->size + kBlockTrailerSize;
    context->size[0] = ROUND_UP(block_size, EBPF_BLOCK_SIZE);

    rocksdb_ctx->stage = stage;
    context->done = false;
}

/*
 * Reads a single key-value pair from context->data + offset.
 * 
 * The key-value pair has the following format:
 *     shared_size (varint32), non_shared_size (varint32), value_length (varint32)
 *     key (non_shared_size bytes)
 *     value_type and seq_no (8 bytes, packed)
 *     value (value_length bytes)
 * 
 * Returns 1 if the key is found, 0 if not, and a negative value on error.
 * Stores the next offset in rocksdb_ctx->data_ctx.offset. If the value
 * is found, it's stored in rocksdb_ctx->data_ctx.value, along with the
 * sequence number and value type.
 */
__noinline int data_block_loop(struct bpf_xrp *context, uint64_t offset) {
    uint8_t *data_block = context->data;
    uint32_t bytes_read;
    volatile uint32_t value_length;
    uint64_t packed_type_seq;
    struct key_size key_size;
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;

    if ((bytes_read = read_key_sizes(context, &key_size, offset)) == 0) {
        bpf_printk("data_block_loop(): failed to read key sizes\n");
        return -EBPF_EINVAL;
    }

    offset += bytes_read;

    // Read value length
    if ((bytes_read = decode_varint32(context, offset)) == 0) {
        bpf_printk("data_block_loop(): failed to read value length\n");
        return -EBPF_EINVAL;
    }

    offset += bytes_read;
    value_length = rocksdb_ctx->varint_ctx.varint32;

    // Remove internal footer from key size
    key_size.non_shared_size -= kNumInternalBytes;

    if (read_key(context, &key_size, offset) < 0) {
        bpf_printk("data_block_loop(): failed to read key\n");
        return -EBPF_EINVAL;
    }

    offset += key_size.non_shared_size;

    /*
     * Key not equal - increment past internal footer and value and move to next
     * iteration.
     */ 
    if (strncmp_key(context) != 0) {
        // TODO if block_key > user_key, user_key is not present. Exit early.
        offset += kNumInternalBytes + value_length;
        rocksdb_ctx->data_ctx.offset = offset;
        return 0;
    }

    // Read the sequence number and value type from the internal key footer
    if (offset > EBPF_DATA_BUFFER_SIZE - kNumInternalBytes) {
        bpf_printk("data_block_loop(): invalid offset before seqno and vt\n");
        return -EBPF_EINVAL;
    }

    packed_type_seq = *(uint64_t *)(data_block + ((offset & (EBPF_DATA_BUFFER_SIZE - 1))));
    unpack_sequence_and_type(packed_type_seq, &rocksdb_ctx->data_ctx.seq, &rocksdb_ctx->data_ctx.vt);

    offset += kNumInternalBytes;

    /* 
     * Offloading reading the value to a separate function led to a verifier
     * failure, so it was kept here.
     */
    if (offset > EBPF_DATA_BUFFER_SIZE - value_length || value_length > MAX_VALUE_LEN) {
        bpf_printk("data_block_loop(): invalid offset before value\n");
        return -EBPF_EINVAL;
    }

    for (int i = 0; i < (value_length & MAX_VALUE_LEN); i++)
        rocksdb_ctx->data_ctx.value[i] = data_block[(offset + i) & (EBPF_DATA_BUFFER_SIZE - 1)];

    rocksdb_ctx->data_ctx.value[value_length & MAX_VALUE_LEN] = '\0';

    return 1;
}

/*
 * Iterates over all key-value pairs in a data block. Starts reading from
 * context->data + block_offset.
 * 
 * Returns 1 if the key is found, 0 if not, and a negative value otherwise.
 */
__noinline int parse_data_block(struct bpf_xrp *context, const uint64_t block_offset) {
    uint8_t index_type;
    int loop_ret, loop_count = 0;
    const int LOOP_MAX = 2000;
    uint32_t num_restarts;
    uint64_t data_end, offset = block_offset;
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;

    if (block_offset > EBPF_BLOCK_SIZE) {
        bpf_printk("parse_data_block(): failed at offset > block size\n");
        return -EBPF_EINVAL;
    }

    // Ensure handle.size isn't greater than the data block size
    if (rocksdb_ctx->handle.size > ROCKSDB_BLOCK_SIZE + BLOCK_FOOTER_FIXED_LEN) {
        bpf_printk("parse_data_block(): failed at handle size > data block size\n");
        return -EBPF_EINVAL;
    }

    if (read_block_footer(context, block_offset, &index_type, &num_restarts) < 0) {
        bpf_printk("parse_data_block(): failed to read block footer\n");
        return -EBPF_EINVAL;
    }

    // TODO check index type

    data_end = block_data_end(block_offset, rocksdb_ctx->handle.size, num_restarts);

    /*
     * Offload each iteration of the loop to data_block_loop(). This allows us
     * to implement complex logic without running afoul of the verifier's jump
     * limit through function-by-function verification.
     * 
     * In order to satisfy the verifier, we artifically cap the loop at LOOP_MAX
     * iterations, which should be enough to read the whole data block. LOOP_MAX
     * was determined based on the eBPF verifier's jump verifier and how many
     * jumps there are in each iteration of the while loop.
     */
    while (offset < data_end && loop_count < LOOP_MAX) {
        loop_ret = data_block_loop(context, offset);
        offset = rocksdb_ctx->data_ctx.offset;
        loop_count++;

        if (loop_ret < 0)
            return loop_ret;
        else if (loop_ret == 0)
            continue;
        else if (loop_ret == 1)
            break;
    }

    if (loop_count >= LOOP_MAX) {
        bpf_printk("parse_data_block(): failed due to loop overflow\n");
        return -EBPF_EINVAL;
    }

    if (offset >= data_end)
        return 0; // not found

    return 1;
}

/*
 * Reads an index value from context->data + offset into
 * rocksdb_ctx->index_ctx.prev_bh.
 * 
 * Index values are block handles to data blocks. For format_version >= 4, index
 * values are delta compressed. When sizes->shared_size == 0, the value is the
 * block handle. Otherwise, the value is a varsignedint64 representing the
 * difference in size between this data block and the previous data block. This
 * can be used to compute the block handle to this data block.
 * 
 * Returns bytes read on success, or 0 on failure.
 */
__inline uint32_t index_read_value(struct bpf_xrp *context, struct key_size *sizes, uint64_t offset) {
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;
    struct block_handle *prev_bh = &rocksdb_ctx->index_ctx.prev_bh;
    uint32_t bytes_read;

    if (sizes->shared_size == 0) {
        if ((bytes_read = read_block_handle(context, prev_bh, offset)) == 0)
            return 0;
    } else {
        int64_t delta_size;

        if ((bytes_read = decode_varsignedint64(context, offset)) == 0)
            return 0;

        delta_size = rocksdb_ctx->varint_ctx.varsigned64;

        // Taken from struct IndexValue::EncodeTo()
        prev_bh->offset = prev_bh->offset + prev_bh->size + kBlockTrailerSize;
        prev_bh->size = prev_bh->size + delta_size; // unsigned + signed
    }

    return bytes_read;
}

/*
 * Reads a single key-value pair from context->data + offset.
 * 
 * The key-value pair has the following format:
 *     shared_size (varint32), non_shared_size (varint32)
 *     key (non_shared_size bytes)
 *     value (block handle or delta_size (varsignedint64))
 * 
 * Returns 1 if the key is found, 0 if not, or a negative value on error.
 * Stores the next offset in rocksdb_ctx->index_ctx.offset and the block handle
 * in rocksdb_ctx->index_ctx.prev_bh.
 */
__noinline int index_block_loop(struct bpf_xrp *context, uint64_t offset) {
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;
    struct key_size key_size;
    uint32_t bytes_read;

    if ((bytes_read = read_key_sizes(context, &key_size, offset)) == 0) {
        bpf_printk("index_block_loop(): failed to read key sizes\n");
        return -EBPF_EINVAL;
    }

    offset += bytes_read;

    if (read_key(context, &key_size, offset) < 0) {
        bpf_printk("index_block_loop(): failed to read key\n");
        return -EBPF_EINVAL;
    }

    offset += key_size.non_shared_size & MAX_KEY_LEN;

    if ((bytes_read = index_read_value(context, &key_size, offset)) == 0) {
        bpf_printk("index_block_loop(): failed to read value\n");
        return -EBPF_EINVAL;
    }

    offset += bytes_read;

    rocksdb_ctx->index_ctx.offset = offset;

    /*
     * The key for a data block is >= the largest key in the data block, but
     * smaller than the smallest key in the next data block. As such, if
     * user_key > current_key, user_key is not in the corresponding data block.
     */
    if (strncmp_key(context) > 0)
        return 0; // not found

    return 1; // found
}

/*
 * Second-level loop for index key-value pair parsing. Starts reading at
 * context->data + offset. Two nested loops allows us to bypass verifier limits.
 * 
 * Returns 1 if the key is found, 0 if not, and a negative value on error.
 */
__noinline int parse_index_block_loop(struct bpf_xrp *context, const uint64_t index_end, uint64_t offset) {
    int loop_ret, loop_count = 0;
    const int LOOP_MAX = 2500;
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;

    /*
     * Offload each iteration of the loop to index_block_loop(). This allows us
     * to implement complex logic without running afoul of the verifier's jump
     * limit through function-by-function verification.
     * 
     * In order to satisfy the verifier, we artifically cap the loop at LOOP_MAX
     * iterations, which should be enough to read the whole data block. LOOP_MAX
     * was determined based on the eBPF verifier's jump verifier and how many
     * jumps there are in each iteration of the while loop.
     */
    while (offset < index_end && loop_count < LOOP_MAX) {
        loop_ret = index_block_loop(context, offset);
        offset = rocksdb_ctx->index_ctx.offset;
        loop_count++;

        if (loop_ret < 0)
            return loop_ret;
        else if (loop_ret == 0)
            continue;
        else if (loop_ret == 1)
            return 1;
    }

    return 0;
}

/*
 * Iterates over all key-value pairs in an index block. Starts reading from
 * context->data + block_offset.
 * 
 * Returns 1 if the key is found, 0 if not, and a negative value otherwise.
 */
__noinline int parse_index_block(struct bpf_xrp *context, const uint64_t block_offset) {
    uint8_t index_type;
    int loop_ret, loop_count = 0;
    const int LOOP_MAX = 2000;
    uint32_t num_restarts;
    uint64_t index_end, offset = block_offset;
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;

    // Assuming index_value_is_delta_encoded, index_type = kBinarySearch, index_key_is_user_key

    if (block_offset > EBPF_BLOCK_SIZE) {
        bpf_printk("parse_index_block(): failed at offset > block size\n");
        return -EBPF_EINVAL;
    }

    if (rocksdb_ctx->handle.size > EBPF_DATA_BUFFER_SIZE) {
        bpf_printk("parse_index_block(): failed at handle size > buffer size\n");
        return -EBPF_EINVAL;
    }

    if (read_block_footer(context, block_offset, &index_type, &num_restarts) < 0) {
        bpf_printk("parse_index_block(): failed to read block footer\n");
        return -EBPF_EINVAL;
    }

    // TODO: check index type

    index_end = block_data_end(block_offset, rocksdb_ctx->handle.size, num_restarts);
    
    /*
     * Offload each iteration of the loop to parse_index_block_loop(). This
     * allows us to implement complex logic without running afoul of the
     * verifier's jump limit through function-by-function verification.
     * 
     * In order to satisfy the verifier, we artifically cap the loop at LOOP_MAX
     * iterations, which should be enough to read the whole data block. LOOP_MAX
     * was determined based on the eBPF verifier's jump verifier and how many
     * jumps there are in each iteration of the while loop.
     * 
     * This is the first level of two nested loops for index parsing. This
     * allows us to bypass the verifier's jump limits.
     */
    while (offset < index_end && loop_count < LOOP_MAX) {
        loop_ret = parse_index_block_loop(context, index_end, offset);
        loop_count++;

        if (loop_ret < 0)
            return loop_ret;
        else if (loop_ret == 0)
            continue;
        else if (loop_ret == 1)
            break;

        offset = rocksdb_ctx->index_ctx.offset;
    }

    if (loop_count >= LOOP_MAX) {
        bpf_printk("parse_index_block(): failed due to loop overflow\n");
        return -EBPF_EINVAL;
    }

    if (offset >= index_end)
        return 0; // not found

    prep_next_stage(context, &rocksdb_ctx->index_ctx.prev_bh, kDataStage);

    return 1; // found
}

/*
 * Read version from footer_ptr + footer_offset into footer.
 * Returns 0 on success or -1 on error.
 */
__inline int footer_read_version(const uint8_t *footer_ptr, struct footer *footer, const uint64_t footer_offset) {
    footer->version = *(uint32_t *)(footer_ptr + footer_offset + VERSION_OFFSET);

    if (!valid_format_version(footer->version)) {
        bpf_printk("Invalid format version: %u\n", footer->version);
        return -1;
    }

    return 0;
}

/*
 * Read checksum type from footer_ptr + footer_offset into footer.
 * Returns 0 on success or -1 on error.
 */
__inline int footer_read_checksum(const uint8_t *footer_ptr, struct footer *footer, const uint64_t footer_offset) {
    footer->checksum = *(uint8_t *)(footer_ptr + footer_offset + CHECKSUM_OFFSET);

    if (!valid_checksum_type(footer->checksum)) {
        bpf_printk("Invalid checksum type: %u\n", footer->checksum);
        return -1;
    }

    return 0;
}

/*
 * Read metadata from footer_ptr + footer_offset into footer.
 * Returns 0 on success or -1 on error.
 */
__inline int64_t footer_read_metadata(const uint8_t *footer_ptr, struct footer *footer, const uint64_t footer_offset) {
    footer->magic_number = *(uint64_t *)(footer_ptr + footer_offset + MAGIC_NUMBER_OFFSET);

    if (footer->magic_number == BLOCK_MAGIC_NUMBER) {
        if (footer_read_version(footer_ptr, footer, footer_offset) < 0)
            return -1;

        if (footer_read_checksum(footer_ptr, footer, footer_offset) < 0)
            return -1;

    } else if (footer->magic_number == LEGACY_BLOCK_MAGIC_NUMBER) {
        footer->version = kLegacyFormatVersion;
        footer->checksum = kLegacyChecksumType;
    } else {
        bpf_printk("Invalid magic number: %lx\n", footer->magic_number);
        return -1;
    }

    return 0;
}

/*
 * Read block handles from context->data + footer_offset into footer. Requires
 * footer->version to be set.
 * 
 * Returns 0 on success, or -1 on error.
 */
__inline uint32_t footer_read_block_handles(struct bpf_xrp *context, struct footer *footer, const uint64_t footer_offset) {
    uint32_t varint_delta;
    uint64_t offset = footer_offset + footer_bh_offset(footer->version);

    // Metaindex block-handle
    if ((varint_delta = read_block_handle(context, &footer->metaindex_handle, offset)) == 0) {
        bpf_printk("Invalid metaindex block handle in footer\n");
        return -1;
    }

    // Index block-handle
    if (read_block_handle(context, &footer->index_handle, offset + varint_delta) == 0) {
        bpf_printk("Invalid index block handle in footer\n");
        return -1;
    }

    return 0;
}

/*
 * Parse the footer and set up metadata for index parsing.
 * Returns 0 on success or a negative value on error.
 */
__noinline int parse_footer(struct bpf_xrp *context, const uint64_t footer_offset) {
    /*
     * Verifier thinks that footer.index_handle may be uninitialized in
     * footer_prep_next_stage(). While footer_read_*() may fail before setting
     * all footer fields, we will error out in those cases, so this isn't an
     * issue.
     * 
     * Hack: zero-initialize `footer` to appease the verifier.
     */
    struct footer footer = {0};

    if (footer_offset < 0 || footer_offset > EBPF_DATA_BUFFER_SIZE - MAX_FOOTER_LEN) {
        bpf_printk("parse_footer(): invalid offset\n");
        return -EBPF_EINVAL;
    }

    if (footer_read_metadata(context->data, &footer, footer_offset) < 0)
        return -EBPF_EINVAL;

    if (footer_read_block_handles(context, &footer, footer_offset) < 0)
        return -EBPF_EINVAL;

    prep_next_stage(context, &footer.index_handle, kIndexStage);

    return 0;
}

/*
 * Reset rocksdb_ebpf_ctx for reading from the next SST file in
 * rocksdb_ctx->file_array.
 */
__noinline int next_sst_file(struct bpf_xrp *context) {
    int curr_idx, data_size;
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;
    struct file_context *file_array = rocksdb_ctx->file_array.array;

    // Is there another file to process?
    if (rocksdb_ctx->file_array.count == rocksdb_ctx->file_array.curr_idx + 1 || rocksdb_ctx->file_array.curr_idx > 15) {
        context->done = true;
        context->next_addr[0] = 0;
        context->size[0] = 0;
        return 0;
    }

    // Prepare to process the next file
    rocksdb_ctx->file_array.curr_idx++;

    // Set the parser state
    curr_idx = rocksdb_ctx->file_array.curr_idx;
    rocksdb_ctx->handle.offset = file_array[curr_idx].offset;
    rocksdb_ctx->handle.size = file_array[curr_idx].bytes_to_read;
    rocksdb_ctx->block_offset = file_array[curr_idx].block_offset;
    rocksdb_ctx->stage = file_array[curr_idx].stage;

    memset(&rocksdb_ctx->data_ctx, 0, sizeof(rocksdb_ctx->data_ctx));
    memset(&rocksdb_ctx->varint_ctx, 0, sizeof(rocksdb_ctx->varint_ctx));
    memset(&rocksdb_ctx->index_ctx, 0, sizeof(rocksdb_ctx->index_ctx));

    // Set the resubmission settings
    data_size = rocksdb_ctx->block_offset + rocksdb_ctx->handle.size + kBlockTrailerSize;
    context->fd_arr[0] = file_array[curr_idx].fd;
    context->next_addr[0] = ROUND_DOWN(file_array[curr_idx].offset, EBPF_BLOCK_SIZE);
    context->size[0] = ROUND_UP(data_size, PAGE_SIZE);
    context->done = false;

    return 0;
}

/*
 * Driver function for the eBPF program. Calls relevant function based on parser
 * state.
 */
SEC("prog")
__u32 rocksdb_lookup(struct bpf_xrp *context) {
    struct rocksdb_ebpf_ctx *rocksdb_ctx = (struct rocksdb_ebpf_ctx *)context->scratch;
    enum parse_stage stage = rocksdb_ctx->stage;
    int ret;

    context->fd_arr[0] = context->cur_fd;

    if (stage == kFooterStage) {
        return parse_footer(context, rocksdb_ctx->block_offset);
    } else if (stage == kIndexStage) {
        if ((ret = parse_index_block(context, rocksdb_ctx->block_offset)) == 1) // found
            return 0;
        else if (ret < 0) // error
            return ret;

        // Not found, go to next SST file
        next_sst_file(context);

        return 0;
    } else if (stage == kDataStage) {
        if ((ret = parse_data_block(context, rocksdb_ctx->block_offset)) == 1) { // found
            rocksdb_ctx->found = 1;
            context->next_addr[0] = 0;
            context->size[0] = 0;
            context->done = true;
        } else if (ret < 0) {
            return ret;
        }

        // Not found, go to next SST file
        next_sst_file(context);

        return 0;
    }

    bpf_printk("Invalid stage: %d\n", stage);
    return -EBPF_EINVAL;
}
