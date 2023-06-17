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
//#define NULL 0
#define true 1
#define false 0

// Varint code
#define VARINT_SHIFT ((unsigned int) 7)
#define VARINT_MSB ((unsigned int) (1 << (VARINT_SHIFT))) // 128 == 0x80

// Returns pointer to one past end of src
__noinline uint32_t decode_varint64(struct bpf_xrp *context, const uint64_t offset, uint8_t limit) {
    const unsigned char *data_buffer = context->data;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    uint64_t result = 0;
    uint32_t counter = 0;

    if (offset < 0 || offset > EBPF_DATA_BUFFER_SIZE - MAX_VARINT64_LEN)
        return 0;

    for (uint8_t shift = 0; shift <= 63; shift += VARINT_SHIFT) {
        unsigned char byte = *(data_buffer + offset + counter);
        counter++;

        if (byte & VARINT_MSB) {
            result |= ((byte & (VARINT_MSB - 1)) << shift);
        }
        else {
            result |= (byte << shift);
            rocksdb_ctx->varint_context.varint64 = result;
            return counter;
        }
    }

    return 0;
}

// Returns pointer to one past end of src
__noinline uint32_t decode_varint32(struct bpf_xrp *context, const uint64_t offset, uint8_t limit) {
    const unsigned char *data_buffer = context->data;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    uint32_t result = 0;
    uint32_t counter = 0;

    if (offset < 0 || offset > EBPF_DATA_BUFFER_SIZE - MAX_VARINT32_LEN)
        return 0;

    for (uint8_t shift = 0; shift <= 27; shift += VARINT_SHIFT) {
        unsigned char byte = *(data_buffer + offset + counter);
        counter++;

        if (byte & VARINT_MSB) {
            result |= ((byte & (VARINT_MSB - 1)) << shift);
        }
        else {
            result |= (byte << shift);
            rocksdb_ctx->varint_context.varint32 = result;
            return counter;
        }
    }

    return 0;
}

__inline int64_t zigzagToI64(uint64_t n) {
    return (n >> 1) ^ -(uint64_t)(n & 1);
}

__noinline uint32_t decode_varsignedint64(struct bpf_xrp *context, const uint64_t offset, uint8_t limit) {
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    uint32_t ret;

    ret = decode_varint64(context, offset, limit);
    rocksdb_ctx->varint_context.varsigned64 = zigzagToI64(rocksdb_ctx->varint_context.varint64);
    return ret;
}

// TODO: fix error return for this
__noinline int strncmp_key(struct bpf_xrp *context) {
    uint8_t n = MAX_KEY_LEN;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    char *user_key = rocksdb_ctx->key;
    char *block_key = rocksdb_ctx->temp_key;

    if (n > MAX_KEY_LEN + 1)
        return -1; // should never happen

    while (n && *user_key && (*user_key == *block_key)) {
        ++user_key;
        ++block_key;
        --n;
    }

    if (n == 0)
        return 0;

    return *(unsigned char *)user_key - *(unsigned char *)block_key;
}

__inline int read_block_footer(struct bpf_xrp *context, const uint32_t offset, uint32_t *block_footer) {
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    uint32_t block_end_offset = offset + rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN;

    if (block_end_offset > EBPF_DATA_BUFFER_SIZE - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN)
        return -1;

    *block_footer = *(uint32_t *)(context->data + block_end_offset);

    return 0;
}

__noinline int data_block_loop(struct bpf_xrp *context, uint32_t data_offset) {
    volatile uint32_t shared_size, non_shared_size, value_length;
    uint32_t varint_return;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    unsigned char *data_key = rocksdb_ctx->temp_key;
    uint8_t *data_block = context->data;
    uint64_t packed_type_seq, seq;
    enum value_type vt;

    memset(data_key, 0, MAX_KEY_LEN + 1);

    varint_return = decode_varint32(context, data_offset, MAX_VARINT32_LEN);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    data_offset += varint_return;
    shared_size = rocksdb_ctx->varint_context.varint32;

    varint_return = decode_varint32(context, data_offset, MAX_VARINT32_LEN);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    data_offset += varint_return;
    non_shared_size = rocksdb_ctx->varint_context.varint32;

    varint_return = decode_varint32(context, data_offset, MAX_VARINT32_LEN);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    data_offset += varint_return;
    value_length = rocksdb_ctx->varint_context.varint32;

    // Remove internal footer from key
    non_shared_size -= kNumInternalBytes;

    if (shared_size > 0) {
        for (int i = 0; i < (shared_size & MAX_KEY_LEN); i++) {
            data_key[i] = rocksdb_ctx->data_context.prev_data_key[i];
        }
    }

    if (shared_size > MAX_KEY_LEN || non_shared_size > MAX_KEY_LEN)
        return -EBPF_EINVAL;

    if (data_offset > EBPF_DATA_BUFFER_SIZE - MAX_KEY_LEN)
        return -EBPF_EINVAL;

    for (int i = 0; i < (non_shared_size & MAX_KEY_LEN); i++) {
        (data_key + (shared_size & MAX_KEY_LEN))[i] = *(data_block + ((data_offset + i) & (EBPF_DATA_BUFFER_SIZE - 1)));
    }

    data_key[(shared_size + non_shared_size) & MAX_KEY_LEN] = '\0';

    for (int i = 0; i < (((shared_size + non_shared_size ) & MAX_KEY_LEN) + 1); i++) {
        rocksdb_ctx->data_context.prev_data_key[i] = data_key[i];
    }

    data_offset += non_shared_size & MAX_KEY_LEN;

    if (strncmp_key(context) != 0) { // key not equal, continue
        data_offset += kNumInternalBytes + value_length;
        rocksdb_ctx->data_context.data_offset = data_offset;
        return 0;
    }

    if (data_offset > EBPF_DATA_BUFFER_SIZE - sizeof(uint64_t))
        return -EBPF_EINVAL;

    packed_type_seq = *(uint64_t *)(data_block + ((data_offset & (EBPF_DATA_BUFFER_SIZE - 1))));
    unpack_sequence_and_type(packed_type_seq, &seq, &vt);

    rocksdb_ctx->data_context.vt = vt;
    rocksdb_ctx->data_context.seq = seq;

    data_offset += kNumInternalBytes;

    for (int i = 0; i < (value_length & MAX_VALUE_LEN); i++) {
        rocksdb_ctx->data_context.value[i] = *(data_block + ((data_offset + i) & (EBPF_DATA_BUFFER_SIZE - 1)));
    }

    rocksdb_ctx->data_context.value[(value_length & MAX_VALUE_LEN)] = '\0';
    return 1;
}

__noinline int parse_data_block(struct bpf_xrp *context, const uint32_t data_block_offset) {
    uint8_t *data_block, index_type;
    uint32_t num_restarts, data_end, block_footer, data_offset = data_block_offset;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    int loop_ret, loop_counter = 0, found = 0;
    const int LOOP_COUNTER_THRESH = 2000;

    if (data_block_offset > EBPF_BLOCK_SIZE || data_block_offset < 0)
        return -EBPF_EINVAL;

    data_block = context->data;

    if (rocksdb_ctx->handle.size > ROCKSDB_BLOCK_SIZE + BLOCK_FOOTER_FIXED_LEN || rocksdb_ctx->handle.size < BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN)
        return -EBPF_EINVAL;

    if (read_block_footer(context, data_block_offset, &block_footer) < 0)
        return -EBPF_EINVAL;

    unpack_index_type_and_num_restarts(block_footer, &index_type, &num_restarts);

    data_end = data_block_offset + rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN - num_restarts * 4;

    while (data_offset < data_end && data_offset < EBPF_DATA_BUFFER_SIZE && loop_counter < LOOP_COUNTER_THRESH) {
        loop_ret = data_block_loop(context, data_offset);
        data_offset = rocksdb_ctx->data_context.data_offset;

        loop_counter++;

        if (loop_ret < 0)
            return loop_ret;
        else if (loop_ret == 0)
            continue;
        else if (loop_ret == 1) {
            found = 1;
            break;
        }
    }

    if (loop_counter >= LOOP_COUNTER_THRESH)
        return -EBPF_EINVAL;

    if (data_offset >= data_end || data_offset >= EBPF_DATA_BUFFER_SIZE) {
        bpf_printk("data offset >= data_end\n");
        return 0; // not found
    }

    return found;
}

__noinline int index_block_loop(struct bpf_xrp *context, uint32_t index_offset) {
    volatile uint32_t shared_size, non_shared_size;
    uint32_t varint_return;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    unsigned char *index_key = rocksdb_ctx->temp_key;
    struct block_handle tmp_data_handle = {};
    uint8_t *index_block = context->data;

    memset(index_key, 0, MAX_KEY_LEN + 1);

    varint_return = decode_varint32(context, index_offset, MAX_VARINT32_LEN);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    index_offset += varint_return;
    shared_size = rocksdb_ctx->varint_context.varint32;

    varint_return = decode_varint32(context, index_offset, MAX_VARINT32_LEN);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    index_offset += varint_return;
    non_shared_size = rocksdb_ctx->varint_context.varint32;

    if (shared_size > 0) {
        for (int i = 0; i < (shared_size & MAX_KEY_LEN); i++) {
            index_key[i] = rocksdb_ctx->index_context.prev_index_key[i];
        }
    }

    if (shared_size > MAX_KEY_LEN || non_shared_size > MAX_KEY_LEN)
        return -EBPF_EINVAL;

    if (index_offset > EBPF_DATA_BUFFER_SIZE - MAX_KEY_LEN)
        return -EBPF_EINVAL;

    for (int i = 0; i < (non_shared_size & MAX_KEY_LEN); i++) {
        (index_key + (shared_size & MAX_KEY_LEN))[i] = *(index_block + ((index_offset + i) & (EBPF_DATA_BUFFER_SIZE - 1)));
    }

    index_key[(shared_size + non_shared_size) & MAX_KEY_LEN] = '\0';

    for (int i = 0; i < (((shared_size + non_shared_size ) & MAX_KEY_LEN) + 1); i++) {
        rocksdb_ctx->index_context.prev_index_key[i] = index_key[i];
    }

    index_offset += non_shared_size & MAX_KEY_LEN;

    if (shared_size == 0) {
        varint_return = decode_varint64(context, index_offset, MAX_VARINT64_LEN);
        if (varint_return == 0)
            return -EBPF_EINVAL;

        index_offset += varint_return;
        tmp_data_handle.offset = rocksdb_ctx->varint_context.varint64;

        varint_return = decode_varint64(context, index_offset, MAX_VARINT64_LEN);
        if (varint_return == 0)
            return -EBPF_EINVAL;

        index_offset += varint_return;
        tmp_data_handle.size = rocksdb_ctx->varint_context.varint64;
    } else {
        int64_t delta_size;

        varint_return = decode_varsignedint64(context, index_offset, MAX_VARINT64_LEN);
        if (varint_return == 0)
            return -EBPF_EINVAL;

        index_offset += varint_return;
        delta_size = rocksdb_ctx->varint_context.varsigned64;

        // struct IndexValue::EncodeTo
        tmp_data_handle.offset = rocksdb_ctx->index_context.prev_data_handle.offset + rocksdb_ctx->index_context.prev_data_handle.size + kBlockTrailerSize;
        tmp_data_handle.size = rocksdb_ctx->index_context.prev_data_handle.size + delta_size;
    }

    rocksdb_ctx->index_context.prev_data_handle = tmp_data_handle;
    rocksdb_ctx->index_context.index_offset = index_offset;

    // key > data block key, key is not in data block
    if (shared_size + non_shared_size > MAX_KEY_LEN)
        return -EBPF_EINVAL;

    
    if (strncmp_key(context) > 0)
        return 0; // not found

    return 1; // found
}

// index_block_offset is initial offset to index, index_ptr_offset is where we are now
__noinline int parse_index_block_loop(struct bpf_xrp *context, const uint64_t index_block_offset, uint64_t index_ptr_offset, uint32_t num_restarts, int *found) {
    int loop_ret, loop_counter = 0;
    const int LOOP_COUNTER_THRESH = 2500;
    uint32_t index_end;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;

    index_end = index_block_offset + rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN - num_restarts * 4;

    while (index_ptr_offset < index_end && index_ptr_offset < EBPF_DATA_BUFFER_SIZE && loop_counter < LOOP_COUNTER_THRESH) {
        loop_ret = index_block_loop(context, index_ptr_offset);
        index_ptr_offset = rocksdb_ctx->index_context.index_offset;

        loop_counter++;

        if (loop_ret < 0)
            return loop_ret;
        else if (loop_ret == 0)
            continue;
        else if (loop_ret == 1) {
            if (found)
                *found = 1;
            break;
        }
    }

    return 0;
}

__noinline int parse_index_block(struct bpf_xrp *context, const uint32_t index_block_offset) {
    uint8_t *index_block, index_type;
    int loop_ret, found = 0, i;
    const int LOOP_COUNTER_THRESH = 2000;
    uint32_t num_restarts, index_end, block_footer, index_offset = index_block_offset;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    uint64_t data_size;

    // Assuming index_value_is_delta_encoded, but index_block_restart_interval == 1 (default)
    // index_type = kBinarySearch and index_key_is_user_key

    if (index_block_offset > EBPF_BLOCK_SIZE || index_block_offset < 0)
        return -EBPF_EINVAL;

    index_block = context->data;

    if (rocksdb_ctx->handle.size > EBPF_DATA_BUFFER_SIZE || rocksdb_ctx->handle.size < BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN)
        return -EBPF_EINVAL;

    if (read_block_footer(context, index_block_offset, &block_footer) < 0)
        return -EBPF_EINVAL;

    unpack_index_type_and_num_restarts(block_footer, &index_type, &num_restarts);
    // TODO: check index type

    index_end = index_block_offset + rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN - num_restarts * 4;

    for (i = 0; i < LOOP_COUNTER_THRESH && index_offset < index_end; i++) {
        loop_ret = parse_index_block_loop(context, index_block_offset, index_offset, num_restarts, &found);

        if (loop_ret < 0)
            return loop_ret;
        if (found)
            break;

        index_offset = rocksdb_ctx->index_context.index_offset;
    }

    if (i >= LOOP_COUNTER_THRESH)
        return -EBPF_EINVAL;

    if (index_offset >= index_end)
        return 0; // not found

    memcpy(&rocksdb_ctx->handle, &rocksdb_ctx->index_context.prev_data_handle, sizeof(struct block_handle));

    rocksdb_ctx->stage = kDataStage;

    context->next_addr[0] = ROUND_DOWN(rocksdb_ctx->handle.offset, EBPF_BLOCK_SIZE);
    //bpf_printk("Address for data block: %llu\n", context->next_addr[0]);
    rocksdb_ctx->offset_in_block = rocksdb_ctx->handle.offset - context->next_addr[0]; // can also mask with EBPF_BLOCK_SIZE - 1
    data_size = rocksdb_ctx->offset_in_block + rocksdb_ctx->handle.size + kBlockTrailerSize;
    context->size[0] = ROUND_UP(data_size, PAGE_SIZE);
    //bpf_printk("data block size: %llu\n", context->size[0]);
    //bpf_printk("data block offset: %llu\n", rocksdb_ctx->offset_in_block);
    context->done = false;

    return found;
}

__inline uint32_t read_block_handle(struct bpf_xrp *context, struct block_handle *bh, uint64_t offset) {
    uint32_t varint_delta, varint_return;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;

    varint_return = decode_varint64(context, offset, MAX_VARINT64_LEN);
    if (varint_return == 0)
        return 0;

    varint_delta = varint_return;
    bh->offset = rocksdb_ctx->varint_context.varint64;

    varint_return = decode_varint64(context, offset + varint_delta, MAX_VARINT64_LEN);
    if (varint_return == 0)
        return 0;

    varint_delta += varint_return;
    bh->size = rocksdb_ctx->varint_context.varint64;

    return varint_delta;
}

__inline int footer_read_version(const uint8_t *footer_ptr, struct footer *footer, const uint64_t footer_offset) {
    footer->version = *(uint32_t *)(footer_ptr + footer_offset + VERSION_OFFSET);

    if (!valid_format_version(footer->version)) {
        bpf_printk("Invalid format version: %u\n", footer->version);
        return -1;
    }

    return 0;
}

__inline int footer_read_checksum(const uint8_t *footer_ptr, struct footer *footer, const uint64_t footer_offset) {
    footer->checksum = *(uint8_t *)(footer_ptr + footer_offset + CHECKSUM_OFFSET);

    if (!valid_checksum_type(footer->checksum)) {
        bpf_printk("Invalid checksum type: %u\n", footer->checksum);
        return -1;
    }

    return 0;
}

// Returns offset within the footer to the footer block handles
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

// Requires footer->version to be set
__inline uint32_t footer_read_block_handles(struct bpf_xrp *context, struct footer *footer, const uint64_t footer_offset) {
    uint32_t varint_delta;
    uint64_t footer_ptr_offset = footer_offset + bh_offset(footer->version);

    // Metaindex block-handle
    varint_delta = read_block_handle(context, &footer->metaindex_handle, footer_ptr_offset);
    if (varint_delta == 0)
        return -1;

    // Index block-handle
    if (read_block_handle(context, &footer->index_handle, footer_ptr_offset + varint_delta) == 0)
        return -1;

    return 0;
}

__inline void footer_prep_next_stage(struct bpf_xrp *context, struct footer *footer) {
    uint64_t index_size;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;

    memcpy(&rocksdb_ctx->handle, &footer->index_handle, sizeof(struct block_handle));

    context->next_addr[0] = ROUND_DOWN(footer->index_handle.offset, EBPF_BLOCK_SIZE);
    rocksdb_ctx->offset_in_block = footer->index_handle.offset - context->next_addr[0];

    index_size = rocksdb_ctx->offset_in_block + footer->index_handle.size + kBlockTrailerSize;
    context->size[0] = ROUND_UP(index_size, PAGE_SIZE);

    rocksdb_ctx->stage = kIndexStage;
    context->done = false;
}

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

    if (footer_offset < 0 || footer_offset > EBPF_DATA_BUFFER_SIZE - MAX_FOOTER_LEN)
        return -EBPF_EINVAL;

    if (footer_read_metadata(context->data, &footer, footer_offset) < 0)
        return -EBPF_EINVAL;

    if (footer_read_block_handles(context, &footer, footer_offset) < 0)
        return -EBPF_EINVAL;

    footer_prep_next_stage(context, &footer);

    return 0;
}

__noinline int next_sst_file(struct bpf_xrp *context) {
    int curr_idx, data_size;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;

    // Is there another file to process?
    if (rocksdb_ctx->file_array.count == rocksdb_ctx->file_array.curr_idx + 1
    || rocksdb_ctx->file_array.curr_idx > 15) {
        context->done = true;
        return 0;
    }

    // Prepare to process the next file
    rocksdb_ctx->file_array.curr_idx++;
    // 1. Set the parser state
    curr_idx = rocksdb_ctx->file_array.curr_idx;
    rocksdb_ctx->handle.offset = rocksdb_ctx->file_array.array[curr_idx].offset;
    rocksdb_ctx->handle.size = rocksdb_ctx->file_array.array[curr_idx].bytes_to_read;
    rocksdb_ctx->offset_in_block = rocksdb_ctx->file_array.array[curr_idx].offset_in_block; // or rocksdb_ctx->handle.offset - context->next_addr[0];
    rocksdb_ctx->stage = rocksdb_ctx->file_array.array[curr_idx].stage;

    // 2. Set the resubmission settings
    data_size = rocksdb_ctx->offset_in_block + rocksdb_ctx->handle.size + kBlockTrailerSize;

    memset(&rocksdb_ctx->data_context, 0, sizeof(rocksdb_ctx->data_context));
    memset(&rocksdb_ctx->varint_context, 0, sizeof(rocksdb_ctx->varint_context));
    memset(&rocksdb_ctx->index_context, 0, sizeof(rocksdb_ctx->index_context));

    context->fd_arr[0] = rocksdb_ctx->file_array.array[curr_idx].fd;
    context->next_addr[0] = ROUND_DOWN(rocksdb_ctx->file_array.array[curr_idx].offset, EBPF_BLOCK_SIZE);
    context->size[0] = ROUND_UP(data_size, PAGE_SIZE);
    context->done = false;
    return 0;
}

SEC("prog")
__u32 rocksdb_lookup(struct bpf_xrp *context) {
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    enum parse_stage stage = rocksdb_ctx->stage;
    int ret = 0;

    context->fd_arr[0] = context->cur_fd;
    bpf_printk("Parse stage: %d\n", stage);

    if (stage == kFooterStage) {
        return parse_footer(context, rocksdb_ctx->offset_in_block);
    } else if (stage == kIndexStage) {
        ret = parse_index_block(context, rocksdb_ctx->offset_in_block);

        if (ret == 1) // found
            return 0;

        rocksdb_ctx->found = 0; // not found
        next_sst_file(context);
        return 0;
    } else if (stage == kDataStage) {
        bpf_printk("Data stage\n");
        ret = parse_data_block(context, rocksdb_ctx->offset_in_block);
        rocksdb_ctx->found = ret == 1;

        if (ret == 1)
            ret = 0;

        if (!rocksdb_ctx->found){
            next_sst_file(context);
            return 0;
        }
    } else {
        return -EBPF_EINVAL;
    }

    context->next_addr[0] = 0;
    context->size[0] = 0;
    context->done = true;

    return ret;
}
