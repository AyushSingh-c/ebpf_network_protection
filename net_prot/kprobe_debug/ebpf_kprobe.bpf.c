#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ebpf_conn_info_maps.bpf.h"

#define ETH_P_IP	0x0800
#define ___constant_swab16(x) ((__u16)(				\
	(((__u16)(x) & (__u16)0x00ffU) << 8) |			\
	(((__u16)(x) & (__u16)0xff00U) >> 8)))
#define __constant_htons(x) ((__be16)___constant_swab16((x)))

SEC("kprobe/__netif_receive_skb")
int sk_buff_from_ingress(struct pt_regs *ctx)
{
    struct sk_buff *skb;
    struct connection_creation_info info = {-1, -1, -1, -1, 0, true};

    if (bpf_probe_read_kernel(&skb, sizeof(skb), (void *)PT_REGS_PARM1(ctx)) == 0)
    {
        unsigned int len;
        if (bpf_probe_read_kernel(&len, sizeof(len), &skb->len) == 0)
        {
            bpf_printk("atleast i got length from __netif_receive_skb");
        }
        unsigned int data_len;
        if (bpf_probe_read_kernel(&data_len, sizeof(data_len), &skb->data_len) == 0)
        {
            bpf_printk("atleast i got data length from __netif_receive_skb");
        }
        void *data;
        if (bpf_probe_read_kernel(&data, sizeof(data), &skb->data) == 0)
        {
            struct ethhdr *eth = data;
            unsigned int len;
            if (bpf_probe_read_kernel(&len, sizeof(len), &skb->len) == 0)
            {
                if (eth + 1 > data + len)
                    return 0;
                u16 h_proto;
                if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), &eth->h_proto) == 0)
                {
                    if (h_proto != __constant_htons(ETH_P_IP))
                    {
                        return 0;
                    }
                }
                else
                {
                    bpf_printk("unable to access h_proto in eth from __netif_receive_skb");
                }

                struct iphdr *ip = (struct iphdr *)(eth + 1);
                if (ip + 1 > data + len)
                {
                    return 0;
                }

                u32 saddr;
                u32 daddr;
                u8 protocol;
                if (bpf_probe_read_kernel(&saddr, sizeof(saddr), &ip->saddr) == 0 &&
                    bpf_probe_read_kernel(&daddr, sizeof(daddr), &ip->daddr) == 0 &&
                    bpf_probe_read_kernel(&protocol, sizeof(protocol), &ip->protocol) == 0)
                {
                    bpf_printk("egress src_ip: %x, dest_ip: %x, proto: %d\n", saddr, daddr, protocol);
                }
                else
                {
                    bpf_printk("unable to access ip info in ip from __netif_receive_skb");
                }

                }
            else
            {
                bpf_printk("unable to access len from __netif_receive_skb");
            }
        }
        // else
        // {
        //     bpf_printk("unable to access data from __netif_receive_skb");
        // }
    }
    else
    {
        bpf_printk("kprobe: __netif_receive_skb unable to get sk_buff");
    }

    if (info.src_ip != -1)
    {
        bpf_printk("Pushing in the ring buff");

        struct connection_creation_info *ringbuf_info;
        ringbuf_info = bpf_ringbuf_reserve(&connection_creation_info_ring_buff, sizeof(struct connection_creation_info), 0);
        if (!ringbuf_info) 
        {
            return 0;
        }  
        __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_creation_info));
        bpf_ringbuf_submit(ringbuf_info, 0);
    }
    return 0;
}

SEC("kprobe/__dev_queue_xmit")
int sk_buff_from_egress(struct pt_regs *ctx) 
{
    struct sk_buff *skb;
    struct connection_creation_info info = {-1, -1, -1, -1, -1, false};

    if (bpf_probe_read_kernel(&skb, sizeof(skb), (void *)PT_REGS_PARM1(ctx)) == 0)
    {
        unsigned int len;
        if (bpf_probe_read_kernel(&len, sizeof(len), &skb->len) == 0)
        {
            bpf_printk("atleast i got length from __dev_queue_xmit");
        }
        unsigned int data_len;
        if (bpf_probe_read_kernel(&data_len, sizeof(data_len), &skb->data_len) == 0)
        {
            bpf_printk("atleast i got data length from __dev_queue_xmit");
        }

        void *data;
        if (bpf_probe_read_kernel(&data, sizeof(data), &skb->data) == 0)
        {
            struct ethhdr *eth = data;
            unsigned int len;
            if (bpf_probe_read_kernel(&len, sizeof(len), &skb->len) == 0)
            {
                if (eth + 1 > data + len)
                    return 0;
                u16 h_proto;
                if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), &eth->h_proto) == 0)
                {
                    if (h_proto != __constant_htons(ETH_P_IP))
                    {
                        return 0;
                    }
                }
                else
                {
                    bpf_printk("unable to access h_proto in eth from __dev_queue_xmit");
                }

                struct iphdr *ip = (struct iphdr *)(eth + 1);
                if (ip + 1 > data + len)
                {
                    return 0;
                }

                u32 saddr;
                u32 daddr;
                u8 protocol;
                if (bpf_probe_read_kernel(&saddr, sizeof(saddr), &ip->saddr) == 0 &&
                    bpf_probe_read_kernel(&daddr, sizeof(daddr), &ip->daddr) == 0 &&
                    bpf_probe_read_kernel(&protocol, sizeof(protocol), &ip->protocol) == 0)
                {
                    bpf_printk("egress src_ip: %x, dest_ip: %x, proto: %d\n", saddr, daddr, protocol);
                }
                else
                {
                    bpf_printk("unable to access ip info in ip from __dev_queue_xmit");
                }

                }
            else
            {
                bpf_printk("unable to access len from __dev_queue_xmit");
            }
        }
        // else
        // {
        //     bpf_printk("unable to access data from __dev_queue_xmit");
        // }
    }
    else
    {
        bpf_printk("kprobe: __dev_queue_xmit unable to get sk_buff");
    }

    if (info.src_ip != -1)
    {
        bpf_printk("Pushing in the ring buff");

        struct connection_creation_info *ringbuf_info;
        ringbuf_info = bpf_ringbuf_reserve(&connection_creation_info_ring_buff, sizeof(struct connection_creation_info), 0);
        if (!ringbuf_info) 
        {
            return 0;
        }  
        __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_creation_info));
        bpf_ringbuf_submit(ringbuf_info, 0);
    }
    return 0;
}

SEC("fentry/__dev_queue_xmit")
int BPF_PROG(fentry_dev_queue_xmit, struct sk_buff *skb) 
{
    u32 len = skb->len;
    u32 protocol = skb->protocol;
    struct net_device *dev = skb->dev;

    void *data;
    bpf_probe_read_kernel(&data, sizeof(data), &skb->data);
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data + skb->len)
        return 0;

    u16 h_proto;
    if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), &eth->h_proto) == 0)
    {
        if (h_proto != __constant_htons(ETH_P_IP))
        {
            return 0;
        }
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data + skb->len)
        return 0;

    struct connection_creation_info info = {0, 0, 0, 0, 0, "", false};

    u32 src_ip;
    u32 dest_ip;
    u8 ip_protocol = 0;
    if (protocol != 8)
        bpf_printk("fentry: __dev_queue_xmit skb->len = %u, skb->protocol = %u, dev->name = %s\n", len, protocol, dev->name);
    if(bpf_probe_read_kernel(&ip_protocol, sizeof(ip_protocol), &ip->protocol) == 0 &&
       bpf_probe_read_kernel(&dest_ip, sizeof(dest_ip), &ip->daddr) == 0 &&
       bpf_probe_read_kernel(&src_ip, sizeof(src_ip), &ip->saddr) == 0)
    {
        info.src_ip = src_ip;
        info.dest_ip = dest_ip;
        bpf_probe_read_kernel(info.dev_name, sizeof(info.dev_name), dev->name);
        info.protocol = ip_protocol;
        if (protocol == IPPROTO_TCP) 
        {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if ((void *)(tcp + 1) > data + skb->len)
                return XDP_PASS;

            __u16 src_port = 0;
            __u16 dest_port = 0;
            if (bpf_probe_read_kernel(&src_port, sizeof(src_port), &tcp->source) == 0 &&
                bpf_probe_read_kernel(&dest_port, sizeof(dest_port), &tcp->dest) == 0)
            {
                info.src_port = src_port;
                info.dest_port = dest_port;
            }
            bpf_printk("TCP Connection for egress");
            bpf_printk("src_ip: %x.%d", info.src_ip, info.src_port);
            bpf_printk("dest_ip: %x.%d", info.dest_ip, info.dest_port);
        }
        else if (protocol == IPPROTO_UDP) 
        {
            struct udphdr *udp = (struct udphdr *)(ip + 1);
            if ((void *)(udp + 1) > data + skb->len)
                return XDP_PASS;

            __u16 src_port = 0;
            __u16 dest_port = 0;
            if (bpf_probe_read_kernel(&src_port, sizeof(src_port), &udp->source) == 0 &&
                bpf_probe_read_kernel(&dest_port, sizeof(dest_port), &udp->dest) == 0)
            {
                info.src_port = src_port;
                info.dest_port = dest_port;
            }

            bpf_printk("UDP Connection for egress");
            bpf_printk("src_ip: %x:%d", info.src_ip, info.src_port);
            bpf_printk("dest_ip: %x:%d", info.dest_ip, info.dest_port);
        }  
        else
        {
            info.src_port = -1;
            info.dest_port = -1;

            bpf_printk("Other Connection for egress src_ip: %x, dest_ip: %x", info.src_ip, info.dest_ip);
        }
    }

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_creation_info_ring_buff, sizeof(struct connection_creation_info), 0);
    if (!ringbuf_info) 
    {
        return 0;
    }   
    bpf_printk("Pushing in the ring buff");

    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_creation_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return 0;
}

SEC("fexit/__netif_receive_skb_core")
int BPF_PROG(fexit_netif_receive_skb, struct sk_buff *pskb, bool pfmemalloc, struct packet_type **ppt_prev, int ret) 
{
    struct sk_buff *skb = pskb;
    u32 len = skb->len;
    u32 protocol = skb->protocol;
    struct net_device *dev = skb->dev;

    void *data;
    bpf_probe_read_kernel(&data, sizeof(data), &skb->data);
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data + skb->len)
        return 0;

    u16 h_proto;
    if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), &eth->h_proto) == 0)
    {
        if (h_proto != __constant_htons(ETH_P_IP))
        {
            bpf_printk("are we looking into netif_receive_skb for bad proto %d", h_proto);
            return 0;
        }
    }
    else
    {
        bpf_printk("are we looking into netif_receive_skb for proto");
    }

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data + skb->len)
        return 0;

    struct connection_creation_info info = {0, 0, 0, 0, 0, "", true};

    u32 src_ip;
    u32 dest_ip;
    u8 ip_protocol = 0;
    bpf_printk("fexit: ___netif_receive_skb skb->len = %u, skb->protocol = %u, dev->name = %s\n", len, protocol, dev->name);
    if(bpf_probe_read_kernel(&ip_protocol, sizeof(ip_protocol), &ip->protocol) == 0 &&
       bpf_probe_read_kernel(&dest_ip, sizeof(dest_ip), &ip->daddr) == 0 &&
       bpf_probe_read_kernel(&src_ip, sizeof(src_ip), &ip->saddr) == 0)
    {
        info.src_ip = src_ip;
        info.dest_ip = dest_ip;
        bpf_probe_read_kernel(info.dev_name, sizeof(info.dev_name), dev->name);
        info.protocol = ip_protocol;
        if (protocol == IPPROTO_TCP) 
        {
            struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
            if ((void *)(tcp + 1) > data + skb->len)
                return XDP_PASS;

            __u16 src_port = 0;
            __u16 dest_port = 0;
            if (bpf_probe_read_kernel(&src_port, sizeof(src_port), &tcp->source) == 0 &&
                bpf_probe_read_kernel(&dest_port, sizeof(dest_port), &tcp->dest) == 0)
            {
                info.src_port = src_port;
                info.dest_port = dest_port;
            }
            bpf_printk("TCP Connection for ingress");
            bpf_printk("src_ip: %x.%d", info.src_ip, info.src_port);
            bpf_printk("dest_ip: %x.%d", info.dest_ip, info.dest_port);
        }
        else if (protocol == IPPROTO_UDP) 
        {
            struct udphdr *udp = (struct udphdr *)(ip + 1);
            if ((void *)(udp + 1) > data + skb->len)
                return XDP_PASS;

            __u16 src_port = 0;
            __u16 dest_port = 0;
            if (bpf_probe_read_kernel(&src_port, sizeof(src_port), &udp->source) == 0 &&
                bpf_probe_read_kernel(&dest_port, sizeof(dest_port), &udp->dest) == 0)
            {
                info.src_port = src_port;
                info.dest_port = dest_port;
            }

            bpf_printk("UDP Connection for ingress");
            bpf_printk("src_ip: %x:%d", info.src_ip, info.src_port);
            bpf_printk("dest_ip: %x:%d", info.dest_ip, info.dest_port);
        }  
        else
        {
            info.src_port = -1;
            info.dest_port = -1;

            bpf_printk("Other Connection for ingress src_ip: %x, dest_ip: %x", info.src_ip, info.dest_ip);
        }
    }

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_creation_info_ring_buff, sizeof(struct connection_creation_info), 0);
    if (!ringbuf_info) 
    {
        return 0;
    }   
    bpf_printk("Pushing in the ring buff");

    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_creation_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
