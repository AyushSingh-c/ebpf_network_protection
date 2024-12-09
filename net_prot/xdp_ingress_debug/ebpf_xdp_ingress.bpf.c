#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "ebpf_conn_info_maps.bpf.h"

SEC("xdp")
int xdp_parser(struct xdp_md *ctx) 
{
    struct connection_creation_info info = {0, 0, 0, 0, 0};
    
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;
    __u32 dest_ip = ip->daddr;
    __u8 protocol = ip->protocol;

    if (protocol == IPPROTO_TCP) 
    {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;

        __u16 src_port = tcp->source;
        __u16 dest_port = tcp->dest;

        info.src_ip = src_ip;
        info.dest_ip = dest_ip;
        info.src_port = src_port;
        info.dest_port = dest_port;
        info.protocol = protocol;

        bpf_printk("TCP Connection");
        bpf_printk("src_ip: %ld.%d", info.src_ip, info.src_port);
        bpf_printk("dest_ip: %ld.%d", info.dest_ip, info.dest_port);
    } 
    else if (protocol == IPPROTO_UDP) 
    {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;

        __u16 src_port = udp->source;
        __u16 dest_port = udp->dest;

        info.src_ip = src_ip;
        info.dest_ip = dest_ip;
        info.src_port = src_port;
        info.dest_port = dest_port;
        info.protocol = protocol;

        bpf_printk("UDP Connection");
        bpf_printk("src_ip: %ld:%d", info.src_ip, info.src_port);
        bpf_printk("dest_ip: %ld:%d", info.dest_ip, info.dest_port);
    } 
    else 
    {
        info.src_ip = src_ip;
        info.dest_ip = dest_ip;
        info.src_port = -1;
        info.dest_port = -1;
        info.protocol = protocol;

        bpf_printk("Other Connection src_ip: %ld, dest_ip: %ld", info.src_ip, info.dest_ip);
    }

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_creation_info_ring_buff, sizeof(struct connection_creation_info), 0);
    if (!ringbuf_info) 
    {
        return XDP_PASS;
    }   
    bpf_printk("Pushing in the ring buff");

    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_creation_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
