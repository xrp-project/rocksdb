#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

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
    const unsigned char *ptr;

    if (offset < 0 || offset > EBPF_DATA_BUFFER_SIZE - MAX_VARINT64_LEN)
        return 0;

    ptr = data_buffer + offset;

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
    const unsigned char *ptr;

    if (offset < 0 || offset > EBPF_DATA_BUFFER_SIZE - MAX_VARINT32_LEN)
        return 0;

    ptr = data_buffer + offset;

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

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

__noinline int strncmp(const char * s1, const char * s2, unsigned long n) {
    if (n > MAX_KEY_LEN + 1)
        return -1; // should never happen

    while ( n && *s1 && ( *s1 == *s2 ) ) {
        ++s1;
        ++s2;
        --n;
    }
    if ( n == 0 ) {
        return 0;
    } else {
        return *(unsigned char *)s1 - *(unsigned char *)s2;
    }
}

__noinline int strncmp_key(struct bpf_xrp *context) {
    uint8_t n = MAX_KEY_LEN;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    char *user_key = rocksdb_ctx->key;
    char *index_key = context->scratch + sizeof(struct rocksdb_ebpf_context);

    if (n > MAX_KEY_LEN + 1)
        return -1; // should never happen
    
    while ( n && *user_key && ( *user_key == *index_key ) ) {
        ++user_key;
        ++index_key;
        --n;
    }
    if ( n == 0 ) {
        return 0;
    } else {
        return *(unsigned char *)user_key - *(unsigned char *)index_key;
    }
}

__noinline int index_block_loop(struct bpf_xrp *context, uint32_t index_offset) {
    volatile uint32_t shared_size, non_shared_size;
    uint32_t varint_return;
    unsigned char *index_key = context->scratch + sizeof(struct rocksdb_ebpf_context);
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
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
    bpf_printk("Index key: %s\n", index_key);

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

__noinline int parse_index_block(struct bpf_xrp *context, uint32_t index_block_offset) {
    uint8_t *index_block, index_type;
    int found;
    const uint8_t *index_iter;
    uint32_t num_restarts, index_end, *block_footer;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    uint32_t index_offset = index_block_offset;

    bpf_printk("index_block_offset: %u\n", index_block_offset);

    // Assuming index_value_is_delta_encoded, but index_block_restart_interval == 1 (default)
    // index_type = kBinarySearch and index_key_is_user_key

    if (index_block_offset > EBPF_BLOCK_SIZE || index_block_offset < 0)
        return -EBPF_EINVAL;

    index_block = context->data;

    index_iter = index_block;

    if (rocksdb_ctx->handle.size > EBPF_DATA_BUFFER_SIZE / 2 + kBlockTrailerSize + BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN || rocksdb_ctx->handle.size < BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN)
        return -EBPF_EINVAL;

    uint32_t block_end_offset = index_block_offset + rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN;
    volatile uint32_t fake_var = 0;

    block_end_offset += fake_var; // prevent compiler from optimizing away bounds check

    if (block_end_offset > EBPF_DATA_BUFFER_SIZE - 4)
        return -EBPF_EINVAL;

    block_footer = (uint32_t *)(index_block + block_end_offset);

    unpack_index_type_and_num_restarts(*block_footer, &index_type, &num_restarts);
    bpf_printk("num_restarts: %u\n", num_restarts);
    // TODO: check index type

    index_end = index_block_offset + rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN - num_restarts * 4;

    found = 0;

    bpf_printk("rocksdb_ctx->handle.size: %lu\n", rocksdb_ctx->handle.size);
    bpf_printk("index_offset: %u\n", index_offset);
    bpf_printk("index_end: %u\n", index_end);

    int loop_ret, loop_counter = 0;
    const int LOOP_COUNTER_THRESH = 1000;
    while (index_offset < index_end && index_offset < EBPF_DATA_BUFFER_SIZE && loop_counter < LOOP_COUNTER_THRESH) {
        loop_ret = index_block_loop(context, index_offset);
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

    bpf_printk("loop counter: %d\n", loop_counter);

    memcpy(&rocksdb_ctx->handle, &rocksdb_ctx->index_context.prev_data_handle, sizeof(struct block_handle));

    rocksdb_ctx->stage = kDataStage;
    return found;
}

__noinline int parse_footer(struct bpf_xrp *context, int32_t footer_offset) {
    uint8_t *footer_ptr;
    const uint8_t *handle, *footer_iter;
    uint32_t varint_return;
    struct footer footer;
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;

    if (footer_offset > EBPF_DATA_BUFFER_SIZE - MAX_FOOTER_LEN || footer_offset < 0)
        return -EBPF_EINVAL;

    footer_ptr = context->data + footer_offset;
    footer_iter = footer_ptr;

    // read magic number
    footer_iter += MAX_FOOTER_LEN - MAGIC_NUM_LEN;
    footer.magic_number = *(uint64_t *)footer_iter;

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

    // Metaindex block handle parsing
    varint_return = decode_varint64(context, footer_iter - (const unsigned char *)context->data, MAX_VARINT64_LEN);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    handle += varint_return;
    footer.metaindex_handle.offset = rocksdb_ctx->varint_context.varint64;

    varint_return = decode_varint64(context, handle - (const unsigned char *)context->data, MAX_VARINT64_LEN);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    handle += varint_return;
    footer.metaindex_handle.size = rocksdb_ctx->varint_context.varint64;

    // Index block handle parsgin
    varint_return = decode_varint64(context, handle - (const unsigned char *)context->data, MAX_VARINT64_LEN);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    handle += varint_return;
    footer.index_handle.offset = rocksdb_ctx->varint_context.varint64;

    varint_return = decode_varint64(context, handle - (const unsigned char *)context->data, MAX_VARINT64_LEN);
    if (varint_return == 0)
        return -EBPF_EINVAL;

    handle += varint_return;
    footer.index_handle.size = rocksdb_ctx->varint_context.varint64;

    bpf_printk("Offset: %ld\n", footer.index_handle.offset);
    bpf_printk("Size: %ld\n", footer.index_handle.size);

    memcpy(&rocksdb_ctx->handle, &footer.index_handle, sizeof(struct block_handle));
    rocksdb_ctx->stage = kIndexStage;

    // need previous multiple of 512
    context->next_addr[0] = (footer.index_handle.offset / EBPF_BLOCK_SIZE) * EBPF_BLOCK_SIZE;
    //bpf_printk("Next addr: %d\n", context->next_addr[0]);
    rocksdb_ctx->footer_len = footer.index_handle.offset - context->next_addr[0];
    context->size[0] = rocksdb_ctx->footer_len + footer.index_handle.size + kBlockTrailerSize;
    context->done = false;

    return 0;
}

SEC("prog")
__u32 rocksdb_lookup(struct bpf_xrp *context) {
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    enum parse_stage stage = rocksdb_ctx->stage;
    bpf_printk("Parse stage: %d\n", stage);

    int ret = 0;

    if (stage == kFooterStage) {
        int32_t footer_offset = rocksdb_ctx->footer_len - MAX_FOOTER_LEN;

        //bpf_printk("Footer offset: %d\n", footer_offset);

        ret = parse_footer(context, footer_offset);

        //if (footer_offset > EBPF_DATA_BUFFER_SIZE - MAX_FOOTER_LEN || footer_offset < 0)
        //    return -EBPF_EINVAL;

        //memcpy(context->scratch, context->data + 4096, MAX_FOOTER_LEN);
        return ret;
    } else if (stage == kIndexStage) {
        // handle index block
        bpf_printk("Index start: %d\n", rocksdb_ctx->footer_len);
        /*if (rocksdb_ctx->footer_len > EBPF_DATA_BUFFER_SIZE - 1024 || rocksdb_ctx->footer_len < 0)
            return -EBPF_EINVAL;

        memcpy(context->scratch, context->data + rocksdb_ctx->footer_len, 1024);*/

        ret = parse_index_block(context, rocksdb_ctx->footer_len);
        /*if (ret == 1)
            memcpy(&rocksdb_ctx->handle, &rocksdb_ctx->index_context.prev_data_handle, sizeof(struct block_handle));*/

    } else if (stage == kDataStage) {
        // handle data block
    } else {
        return -EBPF_EINVAL;
    }

    context->next_addr[0] = 0;
    context->size[0] = 0;
    context->done = true;

    return ret;
}
