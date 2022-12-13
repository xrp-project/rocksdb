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
#define NULL 0
#define true 1
#define false 0

// Varint code
#define VARINT_SHIFT ((unsigned int) 7)
#define VARINT_MSB ((unsigned int) (1 << (VARINT_SHIFT))) // 128 == 0x80

// Returns pointer to one past end of src
const inline unsigned char *decode_varint64(const unsigned char *src, uint64_t *value, uint8_t limit) {
    uint64_t result = 0;
    const unsigned char *ptr = src;

    if (!ptr || !value)
        return NULL;

    for (uint8_t shift = 0; shift <= 63 && src - ptr < limit; shift += VARINT_SHIFT) {
        unsigned char byte = *ptr;
        ptr++;

        if (byte & VARINT_MSB) {
            result |= ((byte & (VARINT_MSB - 1)) << shift);
        }
        else {
            result |= (byte << shift);
            *value = result;
            return ptr;
        }
    }

    return NULL;
}

#undef bpf_printk
#define bpf_printk(fmt, ...)                            \
({                                                      \
        static const char ____fmt[] = fmt;              \
        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                         ##__VA_ARGS__);                \
})

static __inline int parse_footer(struct bpf_xrp *context, int32_t footer_offset) {
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

    handle = decode_varint64(footer_iter, &footer.metaindex_handle.offset, MAX_VARINT64_LEN);
    handle = decode_varint64(handle, &footer.metaindex_handle.size, MAX_VARINT64_LEN);
    if (!handle) {
        bpf_printk("Parsing metaindex handle failed");
        return -EBPF_EINVAL;
    }

    handle = decode_varint64(handle, &footer.index_handle.offset, MAX_VARINT64_LEN);
    handle = decode_varint64(handle, &footer.index_handle.size, MAX_VARINT64_LEN);
    if (!handle) {
        bpf_printk("Parsing index handle failed");
        return -EBPF_EINVAL;
    }

    bpf_printk("Offset: %ld\n", footer.index_handle.offset);
    bpf_printk("Size: %ld\n", footer.index_handle.size);

    memcpy(&rocksdb_ctx->handle, &footer.index_handle, sizeof(struct block_handle));
    rocksdb_ctx->stage = kIndexStage;

    context->next_addr[0] = 0;//footer.index_handle.offset;
    context->size[0] = footer.index_handle.size + kBlockTrailerSize;
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

        if (footer_offset > EBPF_DATA_BUFFER_SIZE - MAX_FOOTER_LEN || footer_offset < 0)
            return -EBPF_EINVAL;

        memcpy(context->scratch, context->data + 4096, MAX_FOOTER_LEN);
        return ret;
    } else if (stage == kIndexStage) {
        // handle index block
        bpf_printk("At index stage\n");
        memcpy(context->scratch, context->data, 1024);
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
