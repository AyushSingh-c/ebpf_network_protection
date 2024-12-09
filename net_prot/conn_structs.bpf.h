#include "conn_info.h"

#include <bpf/bpf_helpers.h>

struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); 
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pkt_info_ring_buff SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); 
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pkt_data_ring_buff SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 10); 
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_setup_ring_buff SEC(".maps");

// todo: need time logic to rem for connection less
struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct connection_config_key));
    __uint(value_size, sizeof(struct connection_config_value));
    __uint(max_entries, 1 << 15);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_config SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 1 << 5);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");