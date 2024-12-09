#ifndef COMMON_MAPS_H
#define COMMON_MAPS_H

#include "src/conn_info.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>


#define TC_ACT_UNSPEC -1
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define ETH_P_IP	0x0800
#define ETH_P_IPV6 0x86DD
#define AF_INET	2
#define AF_INET6	10
#define ETH_ALEN 6
#define EACCES 13
#define ___constant_swab16(x) ((__u16)(				\
	(((__u16)(x) & (__u16)0x00ffU) << 8) |			\
	(((__u16)(x) & (__u16)0xff00U) >> 8)))
#define __constant_htons(x) ((__be16)___constant_swab16((x)))

#define min(x, y)                      \
    ({                                 \
        typeof(x) _min1 = (x);         \
        typeof(y) _min2 = (y);         \
        (void)(&_min1 == &_min2);      \
        _min1 < _min2 ? _min1 : _min2; \
    })

struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 25); 
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pkt_info_ring_buff SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 22); 
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} pkt_data_ring_buff SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 15); 
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_setup_ring_buff SEC(".maps");

// todo: need time logic to rem for connection less
struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct connection_config_key));
    __uint(value_size, sizeof(struct connection_config_value));
    __uint(max_entries, 1 << 10);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_config SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct connection_config_key));
    __uint(value_size, sizeof(struct connection_info));
    __uint(max_entries, 1 << 10);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_info SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(key_size, sizeof(struct ip_lpm_key));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1 << 8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ips SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(key_size, sizeof(struct ip_lpm_key));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1 << 8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} redirect_ips SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct redirection_endpoint));
    __uint(value_size, sizeof(struct redirection_endpoint_mac));
    __uint(max_entries, 1 << 8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} redirect_endpoints SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct redirection_endpoint));
    __uint(value_size, sizeof(struct redirection_endpoint_mac));
    __uint(max_entries, 1 << 8);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} reverse_redirect_endpoints SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u16));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 1 << 5);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} blocked_ports SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(pid_t));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 1 << 10);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} isolation_pids SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(struct network_tuple));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 1 << 10);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} isolation_network_tuple SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 15); 
    __uint(pinning, LIBBPF_PIN_BY_NAME); 
} proc_info_buff SEC(".maps"); 

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(struct net_prot_config));
	__uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME); 
} config_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 25); 
    __uint(pinning, LIBBPF_PIN_BY_NAME); 
} perf_SSL_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1 << 15);
    __type(key, __u64);
    __type(value, struct ssl_carry_info);
    __uint(pinning, LIBBPF_PIN_BY_NAME); 
} SSL_carry_info SEC(".maps");



#endif
