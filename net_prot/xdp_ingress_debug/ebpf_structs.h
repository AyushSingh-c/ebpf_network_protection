#include <linux/types.h>

enum _mde_bpf_map_type {
  BPF_MAP_TYPE_RINGBUF = 27
};

struct connection_creation_info {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u8 protocol;
};