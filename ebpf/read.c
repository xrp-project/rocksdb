#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
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


SEC("prog")
__u32 lookup(struct bpf_xrp *context) {
    context->next_addr[0] = 0;
    context->size[0] = 0;
    context->done = true;

    return 0;
}
