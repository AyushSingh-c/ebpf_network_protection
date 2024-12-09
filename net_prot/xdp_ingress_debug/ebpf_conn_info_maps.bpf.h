#include "ebpf_structs.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18); // 16MB ring buffer
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_creation_info_ring_buff SEC(".maps");