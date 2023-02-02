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
__inline uint32_t decode_varint64(const unsigned char *src, uint64_t *value, uint8_t limit) {
    uint64_t result = 0;
    uint32_t counter = 0;
    const unsigned char *ptr = src;

    if (!ptr || !value)
        return 0;

    for (uint8_t shift = 0; shift <= 63 && src - ptr < limit; shift += VARINT_SHIFT) {
        unsigned char byte = *ptr;
        ptr++;
        counter++;

        if (byte & VARINT_MSB) {
            result |= ((byte & (VARINT_MSB - 1)) << shift);
        }
        else {
            result |= (byte << shift);
            *value = result;
            return counter;
        }
    }

    return 0;
}

// Returns pointer to one past end of src
__inline uint32_t decode_varint32(const unsigned char *src, uint32_t *value, uint8_t limit) {
    uint32_t result = 0;
    const unsigned char *ptr = src;
    uint32_t counter = 0;

    if (!ptr || !value)
        return 0;

    for (uint8_t shift = 0; shift <= 27 && src - ptr < limit; shift += VARINT_SHIFT) {
        unsigned char byte = *ptr;
        ptr++;
        counter++;

        if (byte & VARINT_MSB) {
            result |= ((byte & (VARINT_MSB - 1)) << shift);
        }
        else {
            result |= (byte << shift);
            *value = result;
            return counter;
        }
    }

    return 0;
}

__inline int64_t zigzagToI64(uint64_t n) {
    return (n >> 1) ^ -(uint64_t)(n & 1);
}

__inline uint32_t decode_varsignedint64(const unsigned char *src, int64_t *value, uint8_t limit) {
    uint64_t u = 0;
    uint32_t ret;

    if (!value)
        return 0;
    
    ret = decode_varint64(src, &u, limit);
    *value = zigzagToI64(u);
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

char index_key[MAX_KEY_LEN + 1] = {0};

static __noinline int parse_index_block(struct bpf_xrp *context, uint32_t index_block_offset) {
    uint8_t *index_block, index_type, found;
    const uint8_t *index_iter;
    uint32_t num_restarts, index_end, *block_footer;
    char prev_index_key[MAX_KEY_LEN + 1]= {0};
    struct block_handle tmp_data_handle = {}, prev_data_handle = {};
    struct rocksdb_ebpf_context *rocksdb_ctx = (struct rocksdb_ebpf_context *)context->scratch;
    uint32_t index_offset = index_block_offset;

    // Assuming index_value_is_delta_encoded, but index_block_restart_interval == 1 (default)
    // index_type = kBinarySearch and index_key_is_user_key

    if (index_block_offset > EBPF_BLOCK_SIZE || index_block_offset < 0)
        return -EBPF_EINVAL;

    index_block = context->data;

    index_iter = index_block;

    if (rocksdb_ctx->handle.size > EBPF_DATA_BUFFER_SIZE / 2 + kBlockTrailerSize + BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN || rocksdb_ctx->handle.size < BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN)
        return -EBPF_EINVAL;

    //index_iter += rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN;
    //index_offset += rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN;

    uint32_t block_end_offset = index_block_offset + rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN;
    volatile uint32_t fake_var = 0;

    block_end_offset += fake_var; // prevent compiler from optimizing away bounds check

    if (block_end_offset > EBPF_DATA_BUFFER_SIZE - 4)
        return -EBPF_EINVAL;

    block_footer = (uint32_t *)(index_block + block_end_offset);

    unpack_index_type_and_num_restarts(*block_footer, &index_type, &num_restarts);
    // TODO: check index type

    //printf("\nReading index block...\n");
    //printf("Num restarts: %d, index type: %d\n", num_restarts, index_type);
    index_end = rocksdb_ctx->handle.size - BLOCK_FOOTER_RESTART_INDEX_TYPE_LEN - num_restarts * 4;

    found = 0;

    while (index_offset < index_end && index_offset < EBPF_DATA_BUFFER_SIZE) {
        volatile uint32_t shared_size, non_shared_size;
        unsigned char *index_key = context->scratch + sizeof(struct rocksdb_ebpf_context);
        unsigned char *index_key_ptr = index_key;
        memset(index_key, 0, MAX_KEY_LEN + 1);

        index_offset += decode_varint32(index_block + (index_offset & (EBPF_DATA_BUFFER_SIZE - 1)), &shared_size, MAX_VARINT64_LEN);
        index_offset += decode_varint32(index_block + (index_offset & (EBPF_DATA_BUFFER_SIZE - 1)), &non_shared_size, MAX_VARINT64_LEN);
        /*if (!index_iter) {
            bpf_printk("Parsing index kv failed");
            return -EBPF_EINVAL;
        }*/

        if (shared_size > 0)
            bpf_core_read(index_key, shared_size & MAX_KEY_LEN, (unsigned char *)prev_index_key);

        if (shared_size > MAX_KEY_LEN || non_shared_size > MAX_KEY_LEN)
            return -EBPF_EINVAL;

        index_key_ptr += shared_size;
        //uint32_t size = non_shared_size + shared_size;

        //if (non_shared_size > MAX_KEY_LEN || non_shared_size < 0)
        //    return -EBPF_EINVAL;

        bpf_core_read(index_key + (shared_size & MAX_KEY_LEN), non_shared_size & MAX_KEY_LEN, index_block + (index_offset & (EBPF_DATA_BUFFER_SIZE - 1)));
        index_key[(shared_size + non_shared_size) & MAX_KEY_LEN] = '\0';

        bpf_core_read(prev_index_key, ((shared_size + non_shared_size ) & MAX_KEY_LEN) + 1, index_key);

        index_offset += non_shared_size & MAX_KEY_LEN;

        if (shared_size == 0) {
            index_offset += decode_varint64(index_block + (index_offset & (EBPF_DATA_BUFFER_SIZE - 1)), &tmp_data_handle.offset, MAX_VARINT64_LEN);
            index_offset += decode_varint64(index_block + (index_offset & (EBPF_DATA_BUFFER_SIZE - 1)), &tmp_data_handle.size, MAX_VARINT64_LEN);
            /*if (!index_iter) {
                bpf_printk("Parsing index kv failed");
                return -EBPF_EINVAL;
            }*/
        } else {
            int64_t delta_size;
            index_offset += decode_varsignedint64(index_block + (index_offset & (EBPF_DATA_BUFFER_SIZE - 1)), &delta_size, MAX_VARINT64_LEN);
            /*if (!index_iter) {
                bpf_printk("Parsing index kv failed");
                return -EBPF_EINVAL;
            }*/

            // struct IndexValue::EncodeTo
            tmp_data_handle.offset = prev_data_handle.offset + prev_data_handle.size + kBlockTrailerSize;
            tmp_data_handle.size = prev_data_handle.size + delta_size;
        }

        prev_data_handle = tmp_data_handle;

        // key > data block key, key is not in data block
        if (shared_size + non_shared_size > MAX_KEY_LEN)
            return -EBPF_EINVAL;

        if (strncmp_key(context) > 0)
            continue;

        found = 1;
        break;
    }

    memcpy(&rocksdb_ctx->handle, &tmp_data_handle, sizeof(struct block_handle));

    rocksdb_ctx->stage = kDataStage ;
    return 0;
}

static __noinline int parse_footer(struct bpf_xrp *context, int32_t footer_offset) {
    uint8_t *footer_ptr;
    const uint8_t *handle, *footer_iter;
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

    handle += decode_varint64(footer_iter, &footer.metaindex_handle.offset, MAX_VARINT64_LEN);
    handle += decode_varint64(handle, &footer.metaindex_handle.size, MAX_VARINT64_LEN);
    if (!handle) {
        bpf_printk("Parsing metaindex handle failed");
        return -EBPF_EINVAL;
    }

    handle += decode_varint64(handle, &footer.index_handle.offset, MAX_VARINT64_LEN);
    handle += decode_varint64(handle, &footer.index_handle.size, MAX_VARINT64_LEN);
    if (!handle) {
        bpf_printk("Parsing index handle failed");
        return -EBPF_EINVAL;
    }

    bpf_printk("Offset: %ld\n", footer.index_handle.offset);
    bpf_printk("Size: %ld\n", footer.index_handle.size);

    memcpy(&rocksdb_ctx->handle, &footer.index_handle, sizeof(struct block_handle));
    rocksdb_ctx->stage = kIndexStage;

    // next_addr = (footer.index_handle.offset / EBPF_BLOCK_SIZE) * EBPF_BLOCK_SIZE
    // diff = next_addr - footer.index_handle.offset

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
