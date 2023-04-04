#ifndef _EBPF_EBPF_H_
#define _EBPF_EBPF_H_

#define EBPF_DATA_BUFFER_SIZE (4096)
#define EBPF_SCRATCH_BUFFER_SIZE (1 << 21) // (4 * 4096)
#define EBPF_BLOCK_SIZE 512

#define SYS_READ_XRP 445

#define EBPF_EINVAL 22

int load_bpf_program(char *path);

#endif
