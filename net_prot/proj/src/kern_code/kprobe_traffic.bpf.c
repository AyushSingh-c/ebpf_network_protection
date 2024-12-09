#include "src/kern_code/common_skb_reader.h"


SEC("kprobe/__dev_queue_xmit")
int BPF_KPROBE(kprobe_dev_queue_xmit, struct sk_buff *skb)
{
    // bpf_printk("kprobe_dev_queue_xmit\n");
    __u8 ingress = 0;

    struct pkt_info info;
    __builtin_memset(&info, 0, sizeof(struct pkt_info));

    info.timestamp = bpf_ktime_get_ns();
    info.proc = bpf_get_current_pid_tgid() >> 32;
    info.ingress = 0;

    struct from_sk_buff sk_info;
    __builtin_memset(&sk_info, 0, sizeof(sk_info));
    get_data_from_sk_buff(skb, &sk_info, &ingress);
    if (sk_info.valid != 1)
    {
        bpf_printk("kprobe_dev_queue_xmit: not valid return from get_data_from_sk_buff\n");
        return 0;
    }
    
    info.conn_key.src_ip = sk_info.saddr;
    info.conn_key.src_port = sk_info.sport;
    info.conn_key.dest_ip = sk_info.daddr;
    info.conn_key.dest_port = sk_info.dport;
    info.pk_len = sk_info.pk_len;
    info.ifindex = sk_info.ifindex;
    info.proto.l3_protocol = sk_info.l3_proto;
    info.proto.l4_protocol = sk_info.l4_proto;
    
    struct pkt_info* ring_info = bpf_ringbuf_reserve(&pkt_info_ring_buff, sizeof(struct pkt_info), 0);
    if (!ring_info) 
    {
        bpf_printk("kprobe_dev_queue_xmit: unable to get ring buffer data\n");
        return 0;
    }  
    copy_to_ring(ring_info, &info);

    bpf_ringbuf_submit(ring_info, 0);
    return 0;
}

SEC("kprobe/__netif_receive_skb_core")
int BPF_KPROBE(kprobe_netif_receive_skb, struct sk_buff *skb)
{
    __u8 ingress = 1;

    struct pkt_info info;
    __builtin_memset(&info, 0, sizeof(struct pkt_info));

    info.timestamp = bpf_ktime_get_ns();
    info.proc = bpf_get_current_pid_tgid() >> 32;
    info.ingress = 1;

    struct from_sk_buff sk_info;
    __builtin_memset(&sk_info, 0, sizeof(sk_info));
    get_data_from_sk_buff(skb, &sk_info, &ingress);
    if (sk_info.valid != 1)
    {
        return 0;
    }
    
    info.conn_key.src_ip = sk_info.saddr;
    info.conn_key.src_port = sk_info.sport;
    info.conn_key.dest_ip = sk_info.daddr;
    info.conn_key.dest_port = sk_info.dport;
    info.pk_len = sk_info.pk_len;
    info.ifindex = sk_info.ifindex;
    info.proto.l3_protocol = sk_info.l3_proto;
    info.proto.l4_protocol = sk_info.l4_proto;
    
    struct pkt_info* ring_info = bpf_ringbuf_reserve(&pkt_info_ring_buff, sizeof(struct pkt_info), 0);
    if (!ring_info) 
    {
        return 0;
    }  
    copy_to_ring(ring_info, &info);

    bpf_ringbuf_submit(ring_info, 0);
    return 0;
}

SEC("kprobe/tcp_connect")
int BPF_KPROBE(kprobe_tcp_connect, struct sock *sk)
{
    bpf_printk("kprobe_tcp_connect\n");

    struct sock_common sk_common;
    if (bpf_probe_read_kernel(&sk_common, sizeof(sk_common), &sk->__sk_common) != 0)
    {
        bpf_printk("kprobe_tcp_connect: no sk_common value\n");
        return 0;
    }
    struct connection_setup_info info;
    __builtin_memset(&info, 0, sizeof(info));
    info.timestamp = bpf_ktime_get_ns();
    info.proc = bpf_get_current_pid_tgid() >> 32;
    __u16 right_src_port = ((sk_common.skc_num >> 8) & 0xff) + ((sk_common.skc_num & 0xff) << 8);
    info.conn_key.src_port = right_src_port;
    info.conn_key.dest_port = sk_common.skc_dport;
    info.proto.l4_protocol = IPPROTO_TCP;
    info.ifindex = sk_common.skc_bound_dev_if;
    info.conn_flow = (1<<1) + 0;

    // bpf_printk("tcp_connect start: sport: %x, dport: %x\n", info.conn_key.src_port, info.conn_key.dest_port);

    if (sk_common.skc_family == AF_INET)
    {
        info.conn_key.src_ip.version = IPV4;
        info.conn_key.dest_ip.version = IPV4;
        if (sk_common.skc_rcv_saddr == sk_common.skc_daddr ||  
            bpf_probe_read_kernel(&info.conn_key.src_ip.addr, sizeof(info.conn_key.src_ip.addr), &sk_common.skc_rcv_saddr) != 0 ||
            bpf_probe_read_kernel(&info.conn_key.dest_ip.addr, sizeof(info.conn_key.dest_ip.addr), &sk_common.skc_daddr) != 0)
        {
            bpf_printk("kprobe_tcp_connect: no sk_common sk family INET value\n");
            return 0;
        }
    }
    else if (sk_common.skc_family == AF_INET6)
    {
        info.conn_key.src_ip.version = IPV6;
        info.conn_key.dest_ip.version = IPV6;
        if (sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8 == sk_common.skc_v6_daddr.in6_u.u6_addr8 ||  
            bpf_probe_read_kernel(&info.conn_key.src_ip.addr, sizeof(info.conn_key.src_ip.addr), &sk_common.skc_v6_rcv_saddr) != 0 ||
            bpf_probe_read_kernel(&info.conn_key.dest_ip.addr, sizeof(info.conn_key.dest_ip.addr), &sk_common.skc_v6_daddr) != 0)
        {
            bpf_printk("kprobe_tcp_connect: no sk_common sk family INET6 value\n");
            return 0;
        }
    }
    else
    {
        bpf_printk("kprobe_tcp_connect: sk_common sk family not INET value\n");
        return 0;
    }

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_setup_ring_buff, sizeof(struct connection_setup_info), 0);
    if (!ringbuf_info) 
    {
        bpf_printk("kprobe_tcp_connect: unable to get the ring buff\n");
        return 0;
    }   

    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_setup_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return 0;
}

SEC("kprobe/tcp_conn_request")
int BPF_KPROBE(kprobe_tcp_conn_request, struct request_sock_ops *rsk_ops,
		     const struct tcp_request_sock_ops *af_ops,
		     struct sock *sk, struct sk_buff *skb)
{
    bpf_printk("kprobe_tcp_conn_request\n");
    __u8 ingress = 1;
    struct connection_setup_info info;
    __builtin_memset(&info, 0, sizeof(info));
    info.timestamp = bpf_ktime_get_ns();
    info.proc = bpf_get_current_pid_tgid() >> 32;
    info.proto.l4_protocol = IPPROTO_TCP;
    info.conn_flow = (1<<1) + 1;

    struct from_sk_buff sk_info;
    __builtin_memset(&sk_info, 0, sizeof(sk_info));
    get_data_from_sk_buff(skb, &sk_info, &ingress);
    if (sk_info.valid != 1)
    {
        bpf_printk("kprobe_tcp_conn_request: get sk info is not valid\n");
        return 0;
    }

    info.ifindex = sk_info.ifindex;
    info.conn_key.src_ip = sk_info.saddr;
    info.conn_key.src_port = sk_info.sport;
    info.conn_key.dest_ip = sk_info.daddr;
    info.conn_key.dest_port = sk_info.dport;
    info.proto.l3_protocol = sk_info.l3_proto;
    info.proto.l4_protocol = sk_info.l4_proto;

    // bpf_printk("tcp_connect start : sport: %x, dport: %x\n", info.conn_key.src_port, info.conn_key.dest_port);

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_setup_ring_buff, sizeof(struct connection_setup_info), 0);
    if (!ringbuf_info) 
    {
        bpf_printk("kprobe_tcp_conn_request: unable to get ring buff\n");
        return 0;
    }   
    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_setup_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe_tcp_close, struct sock *sk, long timeout)
{
    // bpf_printk("kprobe_tcp_close\n");
    __u16 skc_family;
    if (bpf_probe_read_kernel(&skc_family, sizeof(skc_family), &sk->__sk_common.skc_family) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
    __be16 skc_dport;
    if (bpf_probe_read_kernel(&skc_dport, sizeof(skc_dport), &sk->__sk_common.skc_dport) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
    __u16 skc_num;
    if (bpf_probe_read_kernel(&skc_num, sizeof(skc_num), &sk->__sk_common.skc_num) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
    int skc_bound_dev_if;
    if (bpf_probe_read_kernel(&skc_bound_dev_if, sizeof(skc_bound_dev_if), &sk->__sk_common.skc_bound_dev_if) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
    __be32 skc_rcv_saddr;
    if (bpf_probe_read_kernel(&skc_rcv_saddr, sizeof(skc_rcv_saddr), &sk->__sk_common.skc_rcv_saddr) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
    __be32 skc_daddr;
    if (bpf_probe_read_kernel(&skc_daddr, sizeof(skc_daddr), &sk->__sk_common.skc_daddr) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
	struct in6_addr skc_v6_daddr;
    if (bpf_probe_read_kernel(&skc_v6_daddr, sizeof(skc_v6_daddr), &sk->__sk_common.skc_v6_daddr) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
	struct in6_addr skc_v6_rcv_saddr;
    if (bpf_probe_read_kernel(&skc_v6_rcv_saddr, sizeof(skc_v6_rcv_saddr), &sk->__sk_common.skc_v6_rcv_saddr) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }

    struct connection_setup_info info;
    __builtin_memset(&info, 0, sizeof(info));
    info.timestamp = bpf_ktime_get_ns();
    info.proc = bpf_get_current_pid_tgid() >> 32;
    info.conn_key.src_port = skc_num;
    info.conn_key.dest_port = skc_dport;
    info.proto.l4_protocol = IPPROTO_TCP;
    info.ifindex = skc_bound_dev_if;
    info.conn_flow = 0 + 0;

    // bpf_printk("tcp_connect: sport end: %x, dport: %x\n", info.conn_key.src_port, info.conn_key.dest_port);

    if (skc_family == AF_INET)
    {
        info.conn_key.src_ip.version = IPV4;
        info.conn_key.dest_ip.version = IPV4;
        if (bpf_probe_read_kernel(&info.conn_key.src_ip.addr, sizeof(info.conn_key.src_ip.addr), &skc_rcv_saddr) != 0 ||
            bpf_probe_read_kernel(&info.conn_key.dest_ip.addr, sizeof(info.conn_key.dest_ip.addr), &skc_daddr) != 0)
        {
            bpf_printk("kprobe_tcp_close: no sk common family in NET\n");
            return 0;
        }
    }
    else if (skc_family == AF_INET6)
    {
        info.conn_key.src_ip.version = IPV6;
        info.conn_key.dest_ip.version = IPV6;
        if (bpf_probe_read_kernel(&info.conn_key.src_ip.addr, sizeof(info.conn_key.src_ip.addr), &skc_v6_rcv_saddr) != 0 ||
            bpf_probe_read_kernel(&info.conn_key.dest_ip.addr, sizeof(info.conn_key.dest_ip.addr), &skc_v6_daddr) != 0)
        {
            bpf_printk("kprobe_tcp_close: no sk common family in NET6\n");
            return 0;
        }
    }
    else
    {
        bpf_printk("kprobe_tcp_close: sk common family in no NET\n");
        return 0;
    }

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_setup_ring_buff, sizeof(struct connection_setup_info), 0);
    if (!ringbuf_info) 
    {
        bpf_printk("kprobe_tcp_close: no ring buff found\n");
        return 0;
    }   

    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_setup_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return 0;
}

SEC("kprobe/tcp_fin")
int BPF_KPROBE(kprobe_tcp_fin, struct sock *sk)
{
    // bpf_printk("kprobe_tcp_fin\n");
    __u16 skc_family;
    if (bpf_probe_read_kernel(&skc_family, sizeof(skc_family), &sk->__sk_common.skc_family) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
    __be16 skc_dport;
    if (bpf_probe_read_kernel(&skc_dport, sizeof(skc_dport), &sk->__sk_common.skc_dport) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
    __u16 skc_num;
    if (bpf_probe_read_kernel(&skc_num, sizeof(skc_num), &sk->__sk_common.skc_num) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
    int skc_bound_dev_if;
    if (bpf_probe_read_kernel(&skc_bound_dev_if, sizeof(skc_bound_dev_if), &sk->__sk_common.skc_bound_dev_if) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
    __be32 skc_rcv_saddr;
    if (bpf_probe_read_kernel(&skc_rcv_saddr, sizeof(skc_rcv_saddr), &sk->__sk_common.skc_rcv_saddr) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
    __be32 skc_daddr;
    if (bpf_probe_read_kernel(&skc_daddr, sizeof(skc_daddr), &sk->__sk_common.skc_daddr) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
	struct in6_addr skc_v6_daddr;
    if (bpf_probe_read_kernel(&skc_v6_daddr, sizeof(skc_v6_daddr), &sk->__sk_common.skc_v6_daddr) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }
	struct in6_addr skc_v6_rcv_saddr;
    if (bpf_probe_read_kernel(&skc_v6_rcv_saddr, sizeof(skc_v6_rcv_saddr), &sk->__sk_common.skc_v6_rcv_saddr) != 0)
    {
        bpf_printk("kprobe_tcp_close: no sk common family\n");
        return 0;
    }

    struct connection_setup_info info;
    __builtin_memset(&info, 0, sizeof(info));
    info.timestamp = bpf_ktime_get_ns();
    info.proc = bpf_get_current_pid_tgid() >> 32;
    __u16 right_src_port = ((skc_num >> 8) & 0xff) + ((skc_num & 0xff) << 8);
    info.conn_key.src_port = right_src_port;
    info.conn_key.dest_port = skc_dport;
    info.proto.l4_protocol = IPPROTO_TCP;
    info.ifindex = skc_bound_dev_if;
    info.conn_flow = 0 + 1;
    // bpf_printk("tcp_connect end: sport: %x, dport: %x\n", info.conn_key.src_port, info.conn_key.dest_port);
    if (skc_family == AF_INET)
    {
        info.conn_key.src_ip.version = IPV4;
        info.conn_key.dest_ip.version = IPV4;
        if (bpf_probe_read_kernel(&info.conn_key.src_ip.addr, sizeof(info.conn_key.src_ip.addr), &skc_rcv_saddr) != 0 ||
            bpf_probe_read_kernel(&info.conn_key.dest_ip.addr, sizeof(info.conn_key.dest_ip.addr), &skc_daddr) != 0)
        {
            bpf_printk("kprobe_tcp_fin: no sk common family INET\n");
            return 0;
        }
    }
    else if (skc_family == AF_INET6)
    {
        info.conn_key.src_ip.version = IPV6;
        info.conn_key.dest_ip.version = IPV6;
        if (bpf_probe_read_kernel(&info.conn_key.src_ip.addr, sizeof(info.conn_key.src_ip.addr), &skc_v6_rcv_saddr) != 0 ||
            bpf_probe_read_kernel(&info.conn_key.dest_ip.addr, sizeof(info.conn_key.dest_ip.addr), &skc_v6_daddr) != 0)
        {
            bpf_printk("kprobe_tcp_fin: no sk common family INET6\n");
            return 0;
        }
    }
    else
    {
        bpf_printk("kprobe_tcp_fin: sk common family no INET\n");
        return 0;
    }

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_setup_ring_buff, sizeof(struct connection_setup_info), 0);
    if (!ringbuf_info) 
    {
        bpf_printk("kprobe_tcp_fin: no ring buff data\n");
        return 0;
    }   
    
    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_setup_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return 0;
}

