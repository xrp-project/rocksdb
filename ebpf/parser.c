#include <linux/bpf.h>
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
__noinline uint32_t decode_varint64_data(struct bpf_xrp *context, uint64_t offset, uint8_t limit) {
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
__noinline uint32_t decode_varint64_scratch(struct bpf_xrp *context, uint64_t offset, uint8_t limit) {
    const unsigned char *data_buffer = context->scratch;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    uint64_t result = 0;
    uint32_t counter = 0;

    if (offset < 0 || offset > EBPF_SCRATCH_BUFFER_SIZE - MAX_VARINT64_LEN)
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
__noinline uint32_t decode_varint64(struct bpf_xrp *context, uint64_t offset, uint8_t limit, int use_data_buffer) {
    if (use_data_buffer)
        return decode_varint64_data(context, offset, limit);
    else
        return decode_varint64_scratch(context, offset, limit);
}

// Returns pointer to one past end of src
__noinline uint32_t decode_varint32_data(struct bpf_xrp *context, uint64_t offset, uint8_t limit) {
    const unsigned char *data_buffer = context->data;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    uint32_t result = 0, counter = 0;

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

// Returns pointer to one past end of src
__noinline uint32_t decode_varint32_scratch(struct bpf_xrp *context, uint64_t offset, uint8_t limit) {
    const unsigned char *data_buffer = context->scratch;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    uint32_t result = 0, counter = 0;

    if (offset < 0 || offset > EBPF_SCRATCH_BUFFER_SIZE - MAX_VARINT32_LEN)
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

// Returns pointer to one past end of src
__noinline uint32_t decode_varint32(struct bpf_xrp *context, uint64_t offset, uint8_t limit, int use_data_buffer) {
    if (use_data_buffer)
        return decode_varint32_data(context, offset, limit);
    else
        return decode_varint32_scratch(context, offset, limit);
}

__inline int64_t zigzagToI64(uint64_t n) {
    return (n >> 1) ^ -(uint64_t)(n & 1);
}

__noinline uint32_t decode_varsignedint64(struct bpf_xrp *context, const uint64_t offset, uint8_t limit, int use_data_buffer) {
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    uint32_t ret;
    
    ret = decode_varint64(context, offset, limit, use_data_buffer);
    rocksdb_ctx->varint_context.varsigned64 = zigzagToI64(rocksdb_ctx->varint_context.varint64);
    return ret;
}

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

    if ( n == 0 ) {
        return 0;
    } else {
        return *(unsigned char *)user_key - *(unsigned char *)block_key;
    }
}

__noinline int data_block_loop(struct bpf_xrp *context, uint32_t data_offset, int use_data_buffer) {
    volatile uint32_t shared_size, non_shared_size, value_length;
    uint32_t varint_return;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    unsigned char *data_key = rocksdb_ctx->temp_key;
    uint64_t packed_type_seq, seq;
    enum value_type vt;
    uint8_t *data_block = context->scratch;

    //data_offset += INITIAL_SCRATCH_DATA_PAGE * PAGE_SIZE;

    memset(data_key, 0, MAX_KEY_LEN + 1);

    varint_return = decode_varint32(context, data_offset, MAX_VARINT32_LEN, use_data_buffer);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    data_offset += varint_return;
    shared_size = rocksdb_ctx->varint_context.varint32;

    varint_return = decode_varint32(context, data_offset, MAX_VARINT32_LEN, use_data_buffer);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    data_offset += varint_return;
    non_shared_size = rocksdb_ctx->varint_context.varint32;

    varint_return = decode_varint32(context, data_offset, MAX_VARINT32_LEN, use_data_buffer);
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

    if (data_offset > EBPF_SCRATCH_BUFFER_SIZE - MAX_KEY_LEN)
        return -EBPF_EINVAL;

    for (int i = 0; i < (non_shared_size & MAX_KEY_LEN); i++) {
        (data_key + (shared_size & MAX_KEY_LEN))[i] = *(data_block + ((data_offset + i) & (EBPF_SCRATCH_BUFFER_SIZE - 1)));
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

    if (data_offset > EBPF_SCRATCH_BUFFER_SIZE - sizeof(uint64_t))
        return -EBPF_EINVAL;

    packed_type_seq = *(uint64_t *)(data_block + ((data_offset & (EBPF_SCRATCH_BUFFER_SIZE - 1))));
    unpack_sequence_and_type(packed_type_seq, &seq, &vt);

    rocksdb_ctx->data_context.vt = vt;
    rocksdb_ctx->data_context.seq = seq;

    data_offset += kNumInternalBytes;

    for (int i = 0; i < (value_length & MAX_VALUE_LEN); i++) {
        rocksdb_ctx->data_context.value[i] = *(data_block + ((data_offset + i) & (EBPF_SCRATCH_BUFFER_SIZE - 1)));
    }

    rocksdb_ctx->data_context.value[(value_length & MAX_VALUE_LEN)] = '\0';

    return 1;
}

__noinline int parse_data_block(struct bpf_xrp *context, uint32_t data_block_offset, int use_data_buffer) {
    uint8_t *data_block, index_type;
    uint32_t num_restarts, data_end, *block_footer, data_offset, block_end_offset;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    volatile uint32_t fake_var = 0;
    int loop_ret, loop_counter = 0, found = 0;
    const int LOOP_COUNTER_THRESH = 2000;

    if (data_block_offset > EBPF_BLOCK_SIZE || data_block_offset < 0)
        return -EBPF_EINVAL;

    data_block = context->scratch;
    data_block_offset += INITIAL_SCRATCH_DATA_PAGE * PAGE_SIZE;

    data_offset = data_block_offset;

    if (rocksdb_ctx->handle.size > ROCKSDB_BLOCK_SIZE + kBlockTrailerSize + BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN || rocksdb_ctx->handle.size < BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN)
        return -EBPF_EINVAL;

    block_end_offset = data_block_offset + rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN;

    block_end_offset += fake_var; // prevent compiler from optimizing away bounds check

    if (block_end_offset > EBPF_SCRATCH_BUFFER_SIZE - 4)
        return -EBPF_EINVAL;

    block_footer = (uint32_t *)(data_block + block_end_offset);

    if (block_end_offset > EBPF_SCRATCH_BUFFER_SIZE - 4)
        return -EBPF_EINVAL;

    block_footer = (uint32_t *)(data_block + block_end_offset);

    unpack_index_type_and_num_restarts(*block_footer, &index_type, &num_restarts);

    data_end = data_block_offset + rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN - num_restarts * 4;

    while (data_offset < data_end && data_offset < EBPF_SCRATCH_BUFFER_SIZE && loop_counter < LOOP_COUNTER_THRESH) {
        loop_ret = data_block_loop(context, data_offset, use_data_buffer);
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

    return found;
}

__noinline int index_block_loop(struct bpf_xrp *context, uint32_t index_offset, int use_data_buffer) {
    volatile uint32_t shared_size, non_shared_size;
    uint32_t varint_return;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    unsigned char *index_key = rocksdb_ctx->temp_key;
    struct block_handle tmp_data_handle = {};

    uint8_t *index_block = context->scratch;
    //index_offset += INITIAL_SCRATCH_DATA_PAGE * PAGE_SIZE;

    memset(index_key, 0, MAX_KEY_LEN + 1);

    varint_return = decode_varint32(context, index_offset, MAX_VARINT32_LEN, use_data_buffer);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    index_offset += varint_return;
    shared_size = rocksdb_ctx->varint_context.varint32;

    varint_return = decode_varint32(context, index_offset, MAX_VARINT32_LEN, use_data_buffer);
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

    if (index_offset > EBPF_SCRATCH_BUFFER_SIZE - MAX_KEY_LEN)
        return -EBPF_EINVAL;

    for (int i = 0; i < (non_shared_size & MAX_KEY_LEN); i++) {
        (index_key + (shared_size & MAX_KEY_LEN))[i] = *(index_block + ((index_offset + i) & (EBPF_SCRATCH_BUFFER_SIZE - 1)));
    }

    index_key[(shared_size + non_shared_size) & MAX_KEY_LEN] = '\0';

    for (int i = 0; i < (((shared_size + non_shared_size ) & MAX_KEY_LEN) + 1); i++) {
        rocksdb_ctx->index_context.prev_index_key[i] = index_key[i];
    }

    index_offset += non_shared_size & MAX_KEY_LEN;

    if (shared_size == 0) {
        varint_return = decode_varint64(context, index_offset, MAX_VARINT64_LEN, use_data_buffer);
        if (varint_return == 0)
            return -EBPF_EINVAL;

        index_offset += varint_return;
        tmp_data_handle.offset = rocksdb_ctx->varint_context.varint64;

        varint_return = decode_varint64(context, index_offset, MAX_VARINT64_LEN, use_data_buffer);
        if (varint_return == 0)
            return -EBPF_EINVAL;

        index_offset += varint_return;
        tmp_data_handle.size = rocksdb_ctx->varint_context.varint64;
    } else {
        int64_t delta_size;

        varint_return = decode_varsignedint64(context, index_offset, MAX_VARINT64_LEN, use_data_buffer);
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

__noinline int parse_index_block(struct bpf_xrp *context, uint32_t index_block_offset, int use_data_buffer) {
    uint8_t *index_block, index_type;
    int loop_ret, loop_counter = 0, found = 0;
    const int LOOP_COUNTER_THRESH = 2000;
    uint32_t num_restarts, index_end, *block_footer, index_offset, block_end_offset;
    uint64_t data_size;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    volatile uint32_t fake_var = 0;

    // Assuming index_value_is_delta_encoded, but index_block_restart_interval == 1 (default)
    // index_type = kBinarySearch and index_key_is_user_key

    if (index_block_offset > EBPF_BLOCK_SIZE || index_block_offset < 0)
        return -EBPF_EINVAL;

    index_block = context->scratch;
    index_block_offset += INITIAL_SCRATCH_DATA_PAGE * PAGE_SIZE;
    index_offset = index_block_offset;

    if (rocksdb_ctx->handle.size > EBPF_SCRATCH_BUFFER_SIZE || rocksdb_ctx->handle.size < BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN)
        return -EBPF_EINVAL;

    block_end_offset = index_block_offset + rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN;

    block_end_offset += fake_var; // prevent compiler from optimizing away bounds check

    if (block_end_offset > EBPF_SCRATCH_BUFFER_SIZE - 4)
        return -EBPF_EINVAL;

    block_footer = (uint32_t *)(index_block + block_end_offset);

    unpack_index_type_and_num_restarts(*block_footer, &index_type, &num_restarts);
    bpf_printk("num_restarts: %u\n", num_restarts);
    // TODO: check index type

    index_end = index_block_offset + rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN - num_restarts * 4;

    while (index_offset < index_end && index_offset < EBPF_SCRATCH_BUFFER_SIZE && loop_counter < LOOP_COUNTER_THRESH) {
        loop_ret = index_block_loop(context, index_offset, use_data_buffer);
        index_offset = rocksdb_ctx->index_context.index_offset;

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

    memcpy(&rocksdb_ctx->handle, &rocksdb_ctx->index_context.prev_data_handle, sizeof(struct block_handle));

    rocksdb_ctx->stage = kDataStage;

    context->next_addr[0] = (rocksdb_ctx->handle.offset / EBPF_BLOCK_SIZE) * EBPF_BLOCK_SIZE;
    bpf_printk("Address for data block: %llu\n", context->next_addr[0]);
    rocksdb_ctx->footer_len = rocksdb_ctx->handle.offset - context->next_addr[0]; // can also mask with EBPF_BLOCK_SIZE - 1
    context->size[0] = EBPF_DATA_BUFFER_SIZE; //rocksdb_ctx->footer_len + rocksdb_ctx->handle.size + kBlockTrailerSize;
    bpf_printk("data block size: %llu\n", context->size[0]);
    bpf_printk("data block offset: %llu\n", rocksdb_ctx->footer_len);
    context->done = false;

    data_size = rocksdb_ctx->footer_len + rocksdb_ctx->handle.size + kBlockTrailerSize;

    /*
    if (data_size > EBPF_DATA_BUFFER_SIZE) {
        rocksdb_ctx->copy_data = 1;
        rocksdb_ctx->data_copy_context.initial_offset = context->next_addr[0];
        rocksdb_ctx->data_copy_context.total_size = data_size;
        rocksdb_ctx->data_copy_context.size_remaining = data_size;
        rocksdb_ctx->data_copy_context.nr_pages = 0;
    } else {
        rocksdb_ctx->copy_data = 0;
    }
    */

    rocksdb_ctx->copy_data = 1;
    rocksdb_ctx->data_copy_context.initial_offset = context->next_addr[0];
    rocksdb_ctx->data_copy_context.total_size = data_size;
    rocksdb_ctx->data_copy_context.size_remaining = data_size;
    rocksdb_ctx->data_copy_context.nr_pages = 0;

    return found;
}

__noinline int parse_footer(struct bpf_xrp *context, uint64_t footer_offset) {
    uint8_t *footer_ptr;
    const uint8_t *handle, *footer_iter;
    uint32_t varint_return;
    uint64_t index_size;
    struct footer footer;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;

    footer_offset += INITIAL_SCRATCH_DATA_PAGE * PAGE_SIZE;

    if (footer_offset > EBPF_SCRATCH_BUFFER_SIZE - MAX_FOOTER_LEN || footer_offset < 0)
        return -EBPF_EINVAL;

    footer_ptr = context->scratch + footer_offset;
    footer_iter = footer_ptr;

    // read magic number
    footer_iter += MAX_FOOTER_LEN - MAGIC_NUM_LEN;
    footer.magic_number = *(uint64_t *)footer_iter;
    //bpf_printk("Magic number: %lx\n", *(uint64_t *)footer_iter);

    if (footer.magic_number == BLOCK_MAGIC_NUMBER) {
        // read version
        footer_iter -= VERSION_LEN;
        footer.version = *(uint32_t *)footer_iter;

        if (!valid_format_version(footer.version)) {
            bpf_printk("Invalid format version: %u", footer.version);
            return -EBPF_EINVAL;
        }

        // read checksum type
        footer.checksum = *(uint8_t *)footer_ptr;
        if (!valid_checksum_type(footer.checksum)) {
            bpf_printk("Invalid checksum type: %u", footer.checksum);
            return -EBPF_EINVAL;
        }

        // set pointer to start of block handles
        footer_iter = footer_ptr + CHECKSUM_LEN;
    } else if (footer.magic_number == LEGACY_BLOCK_MAGIC_NUMBER) {
        footer.version = kLegacyFormatVersion;
        footer.checksum = kLegacyChecksumType;

        // set pointer to start of block handles
        footer_iter -= 2 * MAX_BLOCK_HANDLE_LEN;
    } else {
        bpf_printk("Invalid magic number: %lx\n", footer.magic_number);
        return -EBPF_EINVAL;
    }

    handle = footer_iter;

    // Metaindex block-handle parsing
    varint_return = decode_varint64(context, footer_iter - (const unsigned char *)context->scratch, MAX_VARINT64_LEN, 0);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    handle += varint_return;
    footer.metaindex_handle.offset = rocksdb_ctx->varint_context.varint64;

    varint_return = decode_varint64(context, handle - (const unsigned char *)context->scratch, MAX_VARINT64_LEN, 0);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    handle += varint_return;
    footer.metaindex_handle.size = rocksdb_ctx->varint_context.varint64;

    // Index block-handle parsing
    varint_return = decode_varint64(context, handle - (const unsigned char *)context->scratch, MAX_VARINT64_LEN, 0);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    handle += varint_return;
    footer.index_handle.offset = rocksdb_ctx->varint_context.varint64;

    varint_return = decode_varint64(context, handle - (const unsigned char *)context->scratch, MAX_VARINT64_LEN, 0);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    handle += varint_return;
    footer.index_handle.size = rocksdb_ctx->varint_context.varint64;

    memcpy(&rocksdb_ctx->handle, &footer.index_handle, sizeof(struct block_handle));
    rocksdb_ctx->stage = kIndexStage;

    // need previous multiple of 512
    context->next_addr[0] = (footer.index_handle.offset / EBPF_BLOCK_SIZE) * EBPF_BLOCK_SIZE;
    rocksdb_ctx->footer_len = footer.index_handle.offset - context->next_addr[0];
    context->size[0] = EBPF_DATA_BUFFER_SIZE; //rocksdb_ctx->footer_len + footer.index_handle.size + kBlockTrailerSize;
    context->done = false;

    index_size = rocksdb_ctx->footer_len + footer.index_handle.size + kBlockTrailerSize;

    /*
    if (index_size > EBPF_DATA_BUFFER_SIZE) {
        rocksdb_ctx->copy_data = 1;
        rocksdb_ctx->data_copy_context.initial_offset = context->next_addr[0];
        rocksdb_ctx->data_copy_context.total_size = index_size;
        rocksdb_ctx->data_copy_context.size_remaining = index_size;
        rocksdb_ctx->data_copy_context.nr_pages = 0;
    } else {
        rocksdb_ctx->copy_data = 0;
    }
    */

    rocksdb_ctx->copy_data = 1;
    rocksdb_ctx->data_copy_context.initial_offset = context->next_addr[0];
    rocksdb_ctx->data_copy_context.total_size = index_size;
    rocksdb_ctx->data_copy_context.size_remaining = index_size;
    rocksdb_ctx->data_copy_context.nr_pages = 0;

    return 0;
}

__noinline int copy_block(struct bpf_xrp *context) {
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    struct data_copy_context *data_copy_context = &rocksdb_ctx->data_copy_context;
    int i, ret;

    for (i = 0; i < EBPF_DATA_BUFFER_SIZE; i++) {
        *(context->scratch + (((data_copy_context->nr_pages + INITIAL_SCRATCH_DATA_PAGE) * EBPF_DATA_BUFFER_SIZE + i) & (EBPF_SCRATCH_BUFFER_SIZE - 1))) = context->data[i];
    }

    if (data_copy_context->size_remaining <= EBPF_DATA_BUFFER_SIZE) {
        data_copy_context->size_remaining = 0;
        ret = COPY_DONE;
    } else {
        data_copy_context->size_remaining -= EBPF_DATA_BUFFER_SIZE;
        ret = COPY_MORE;
    }
    data_copy_context->nr_pages++;

    return ret;
}

SEC("prog")
__u32 rocksdb_lookup(struct bpf_xrp *context) {
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    enum parse_stage stage = rocksdb_ctx->stage;
    int ret = 0, use_data_buffer = 0;

    bpf_printk("Parse stage: %d\n", stage);

    if (stage == kFooterStage) {
        uint64_t footer_offset = rocksdb_ctx->footer_len - MAX_FOOTER_LEN;
        copy_block(context);
        ret = parse_footer(context, footer_offset);

        return ret;
    } else if (stage == kIndexStage) {
        if (rocksdb_ctx->copy_data) {
            if (copy_block(context) == COPY_MORE) {
                context->next_addr[0] = rocksdb_ctx->data_copy_context.initial_offset + rocksdb_ctx->data_copy_context.nr_pages * PAGE_SIZE;
                context->size[0] = EBPF_DATA_BUFFER_SIZE;
                context->done = false;
                return 0;
            } else {
                use_data_buffer = 0;
                rocksdb_ctx->copy_data = 0;
            }
        }

        // handle index block
        ret = parse_index_block(context, rocksdb_ctx->footer_len, use_data_buffer);

        if (ret == 1) // found
            return 0;

        rocksdb_ctx->found = 0; // not found

    } else if (stage == kDataStage) {
        if (rocksdb_ctx->copy_data) {
            if (copy_block(context) == COPY_MORE) {
                context->next_addr[0] = rocksdb_ctx->data_copy_context.initial_offset + rocksdb_ctx->data_copy_context.nr_pages * PAGE_SIZE;
                context->size[0] = EBPF_DATA_BUFFER_SIZE;
                context->done = false;
                return 0;
            } else {
                use_data_buffer = 0;
                rocksdb_ctx->copy_data = 0;
            }
        }

        ret = parse_data_block(context, rocksdb_ctx->footer_len, use_data_buffer);
        rocksdb_ctx->found = ret == 1;
        if (ret == 1)
            ret = 0;
    } else {
        return -EBPF_EINVAL;
    }

    context->next_addr[0] = 0;
    context->size[0] = 0;
    context->done = true;

    return ret;
}
