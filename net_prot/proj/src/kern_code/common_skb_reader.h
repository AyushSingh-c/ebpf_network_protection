#ifndef COMMON_SKBREADER_H
#define COMMON_SKBREADER_H

#include "src/vmlinux.h"
#include "src/conn_structs.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ETH_P_IP	0x0800
#define ETH_P_IPV6 0x86DD
#define AF_INET	2
#define AF_INET6	10
#define ETH_ALEN 6
#define ___constant_swab16(x) ((__u16)(				\
	(((__u16)(x) & (__u16)0x00ffU) << 8) |			\
	(((__u16)(x) & (__u16)0xff00U) >> 8)))
#define __constant_htons(x) ((__be16)___constant_swab16((x)))


static void copy_to_ring(struct pkt_info* ring_info, struct pkt_info* info)
{
    if ( ring_info == NULL || info == NULL )
    {
        return;
    }
    ring_info->timestamp = info->timestamp;
    ring_info->ifindex = info->ifindex;
    ring_info->proc = info->proc;
    ring_info->proc = info->proc;
    ring_info->pk_len = info->pk_len;
    ring_info->ingress = info->ingress;
    ring_info->proto = info->proto;
    ring_info->conn_key = info->conn_key;
}

static void* get_eth_header_for_ingress(struct sk_buff *skb)
{
    void *head;
    bpf_probe_read_kernel(&head, sizeof(head), &skb->head);
    __u16 mac_header;
    if(bpf_probe_read_kernel(&mac_header, sizeof(mac_header), &skb->mac_header) != 0)
    {
        return NULL;
    }

    struct ethhdr *eth = (struct ethhdr *)(head + mac_header);
    return eth;
}

static void* get_eth_header_for_egress(struct sk_buff *skb)
{
    if (skb == NULL)
        return NULL;

    void* head;
    sk_buff_data_t end;
    if(bpf_probe_read_kernel(&end, sizeof(end), &skb->end) != 0 ||
        (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0))
    {
        return NULL;
    }

    void *data;
    bpf_probe_read_kernel(&data, sizeof(data), &skb->data);
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > head + end)
    {
        return NULL;
    }
    return eth;
}

static void get_data_from_sk_buff(struct sk_buff *skb, struct from_sk_buff *ret, __u8* ingress)
{
    if (skb == NULL || ingress == NULL || ret == NULL)
    {
        bpf_printk("get_data_from_sk_buff: invalid arguments\n");
        return;
    }

    void* head;
    sk_buff_data_t end;
    if(bpf_probe_read_kernel(&end, sizeof(end), &skb->end) != 0 ||
        (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0))
    {
        bpf_printk("get_data_from_sk_buff: unable to read skb buffer\n");
        return;
    }
    struct net_device *dev;
    if (bpf_probe_read_kernel(&dev, sizeof(dev), &skb->dev) == 0)
    {
        bpf_probe_read_kernel(&ret->ifindex, sizeof(ret->ifindex), &dev->ifindex);
    }

    struct ethhdr *eth;
    if (*ingress == 0)
        eth = (struct ethhdr *)get_eth_header_for_egress(skb);
    else    
        eth = (struct ethhdr *)get_eth_header_for_ingress(skb);
    if (eth == NULL || ((void *)(eth + 1) > head + end))
    {
        bpf_printk("get_data_from_sk_buff: unable to read eth buffer\n");
        return;
    }

    u16 h_proto;
    if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), &eth->h_proto) == 0)
    {
        if (h_proto != __constant_htons(ETH_P_IP) && h_proto != __constant_htons(ETH_P_IPV6))
        {
            // bpf_printk("get_data_from_sk_buff: unable to read correct eth proto buffer %d\n", h_proto);
            return;  //only support IPv4 and IPv6
        }
    }
    ret->l3_proto = h_proto;

    void* after_ip;
    if (h_proto == __constant_htons(ETH_P_IP))
    {
        struct iphdr *ip = (struct iphdr *)(eth + 1);
        if ((void *)(ip + 1) > head + end)
        {
            bpf_printk("get_data_from_sk_buff: unable to read ipv4 buffer\n");
            return;
        }
        bpf_probe_read_kernel(&ret->pk_len, sizeof(ret->pk_len), &skb->len);
        ret->saddr.version = IPV4;
        ret->daddr.version = IPV4;
        if (bpf_probe_read_kernel(&ret->saddr.addr, sizeof(ret->saddr.addr), &ip->saddr) != 0 ||
            bpf_probe_read_kernel(&ret->daddr.addr, sizeof(ret->daddr.addr), &ip->daddr) != 0 ||
            bpf_probe_read_kernel(&ret->l4_proto, sizeof(ret->l4_proto), &ip->protocol) != 0)
        {
            bpf_printk("get_data_from_sk_buff: unable to read ipv4 ptr buffer\n");
            return;
        }

        after_ip = (void*)(ip + 1);
    }
    else
    {
        struct ipv6hdr *ip = (struct ipv6hdr *)(eth + 1);
        if ((void *)(ip + 1) > head + end)
        {
            bpf_printk("get_data_from_sk_buff: unable to read ipv6 buffer\n");
            return;
        }
        bpf_probe_read_kernel(&ret->pk_len, sizeof(ret->pk_len), &skb->len);
        ret->saddr.version = IPV6;
        ret->daddr.version = IPV6;

        if (bpf_probe_read_kernel(&ret->saddr.addr, sizeof(ret->saddr.addr), &ip->saddr) != 0 ||
            bpf_probe_read_kernel(&ret->daddr.addr, sizeof(ret->daddr.addr), &ip->daddr) != 0 ||
            bpf_probe_read_kernel(&ret->l4_proto, sizeof(ret->l4_proto), &ip->nexthdr) != 0)
        {
            bpf_printk("get_data_from_sk_buff: unable to read ipv6 ptr buffer\n");
            return;
        }

        after_ip = (void*)(ip + 1);
    }

    if (ret->l4_proto == IPPROTO_TCP) 
    {
        struct tcphdr *tcp = (struct tcphdr *)(after_ip);
        if ((void *)(tcp + 1) > head + end)
        {
            bpf_printk("get_data_from_sk_buff: unable to read tcp buffer\n");
            return;
        }

        bpf_probe_read_kernel(&ret->dport, sizeof(ret->dport), &tcp->dest);
        bpf_probe_read_kernel(&ret->sport, sizeof(ret->sport), &tcp->source);
    }
    else if (ret->l4_proto == IPPROTO_UDP) 
    {
        struct udphdr *udp = (struct udphdr *)(after_ip);
        if ((void *)(udp + 1) > head + end)
        {          
            bpf_printk("get_data_from_sk_buff: unable to read udp buffer\n");
            return;
        }
        
        bpf_probe_read_kernel(&ret->dport, sizeof(ret->dport), &udp->dest);
        bpf_probe_read_kernel(&ret->sport, sizeof(ret->sport), &udp->source);
    }  
    else
    {
        ret->sport = -1;
        ret->dport = -1;
    }

    ret->valid = 1;
    return;
}



#endif