#include "src/kern_code/common_skb_reader.h"

SEC("fentry/__dev_queue_xmit")
int BPF_PROG(fentry_dev_queue_xmit, struct sk_buff *skb) 
{
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

// depending on the kernel we need to adjust this
// SEC("fentry/__netif_receive_skb_core")
// int BPF_PROG(fentry_netif_receive_skb, struct sk_buff *skb) 
// {
//     bpf_printk("getting data from sk_buff from netif_receive_skb_core\n");
//     __u8 ingress = 1;

//     struct pkt_info info;
//     __builtin_memset(&info, 0, sizeof(struct pkt_info));

//     info.timestamp = bpf_ktime_get_ns();
//     info.proc = bpf_get_current_pid_tgid() >> 32;
//     info.ingress = 1;

//     struct from_sk_buff sk_info;
//     __builtin_memset(&sk_info, 0, sizeof(sk_info));
//     get_data_from_sk_buff(skb, &sk_info, &ingress);
//     if (sk_info.valid != 1)
//     {
//         return 0;
//     }
    
//     info.conn_key.src_ip = sk_info.saddr;
//     info.conn_key.src_port = sk_info.sport;
//     info.conn_key.dest_ip = sk_info.daddr;
//     info.conn_key.dest_port = sk_info.dport;
//     info.pk_len = sk_info.pk_len;
//     info.ifindex = sk_info.ifindex;
//     info.proto.l3_protocol = sk_info.l3_proto;
//     info.proto.l4_protocol = sk_info.l4_proto;
    
//     struct pkt_info* ring_info = bpf_ringbuf_reserve(&pkt_info_ring_buff, sizeof(struct pkt_info), 0);
//     if (!ring_info) 
//     {
//         return 0;
//     }  
//     copy_to_ring(ring_info, &info);

//     bpf_ringbuf_submit(ring_info, 0);
//     return 0;
// }

SEC("fentry/tcp_connect")
int BPF_PROG(fentry_tcp_connect, struct sock *sk)
{
    struct connection_setup_info info;
    __builtin_memset(&info, 0, sizeof(info));
    info.timestamp = bpf_ktime_get_ns();
    info.proc = bpf_get_current_pid_tgid() >> 32;
    __u16 right_src_port = ((sk->__sk_common.skc_num >> 8) & 0xff) + ((sk->__sk_common.skc_num & 0xff) << 8);
    info.conn_key.src_port = right_src_port;
    info.conn_key.dest_port = sk->__sk_common.skc_dport;
    info.proto.l4_protocol = IPPROTO_TCP;
    info.ifindex = sk->__sk_common.skc_bound_dev_if;
    info.conn_flow = (1<<1) + 0;

    // bpf_printk("tcp_connect start: sport: %x, dport: %x\n", info.conn_key.src_port, info.conn_key.dest_port);

    if (sk->__sk_common.skc_family == AF_INET)
    {
        info.conn_key.src_ip.version = IPV4;
        info.conn_key.dest_ip.version = IPV4;
        if (sk->__sk_common.skc_rcv_saddr == sk->__sk_common.skc_daddr ||  
            bpf_probe_read_kernel(&info.conn_key.src_ip.addr, sizeof(info.conn_key.src_ip.addr), &sk->__sk_common.skc_rcv_saddr) != 0 ||
            bpf_probe_read_kernel(&info.conn_key.dest_ip.addr, sizeof(info.conn_key.dest_ip.addr), &sk->__sk_common.skc_daddr) != 0)
        {
            return 0;
        }
    }
    else if (sk->__sk_common.skc_family == AF_INET6)
    {
        info.conn_key.src_ip.version = IPV6;
        info.conn_key.dest_ip.version = IPV6;
        if (sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8 == sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8 ||  
            bpf_probe_read_kernel(&info.conn_key.src_ip.addr, sizeof(info.conn_key.src_ip.addr), &sk->__sk_common.skc_v6_rcv_saddr) != 0 ||
            bpf_probe_read_kernel(&info.conn_key.dest_ip.addr, sizeof(info.conn_key.dest_ip.addr), &sk->__sk_common.skc_v6_daddr) != 0)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_setup_ring_buff, sizeof(struct connection_setup_info), 0);
    if (!ringbuf_info) 
    {
        return 0;
    }   

    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_setup_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return 0;
}

SEC("fentry/tcp_conn_request")
int BPF_PROG(fentry_tcp_conn_request, struct request_sock_ops *rsk_ops,
		     const struct tcp_request_sock_ops *af_ops,
		     struct sock *sk, struct sk_buff *skb)
{
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
        return 0;
    }   
    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_setup_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return 0;
}

SEC("fentry/tcp_close")
int BPF_PROG(fentry_tcp_close, struct sock *sk)
{
    struct connection_setup_info info;
    __builtin_memset(&info, 0, sizeof(info));
    info.timestamp = bpf_ktime_get_ns();
    info.proc = bpf_get_current_pid_tgid() >> 32;
    info.conn_key.src_port = sk->__sk_common.skc_num;
    info.conn_key.dest_port = sk->__sk_common.skc_dport;
    info.proto.l4_protocol = IPPROTO_TCP;
    info.ifindex = sk->__sk_common.skc_bound_dev_if;
    info.conn_flow = 0 + 0;

    // bpf_printk("tcp_connect: sport end: %x, dport: %x\n", info.conn_key.src_port, info.conn_key.dest_port);

    if (sk->__sk_common.skc_family == AF_INET)
    {
        info.conn_key.src_ip.version = IPV4;
        info.conn_key.dest_ip.version = IPV4;
        if (sk->__sk_common.skc_rcv_saddr == sk->__sk_common.skc_daddr ||  
            bpf_probe_read_kernel(&info.conn_key.src_ip.addr, sizeof(info.conn_key.src_ip.addr), &sk->__sk_common.skc_rcv_saddr) != 0 ||
            bpf_probe_read_kernel(&info.conn_key.dest_ip.addr, sizeof(info.conn_key.dest_ip.addr), &sk->__sk_common.skc_daddr) != 0)
        {
            return 0;
        }
    }
    else if (sk->__sk_common.skc_family == AF_INET6)
    {
        info.conn_key.src_ip.version = IPV6;
        info.conn_key.dest_ip.version = IPV6;
        if (sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8 == sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8 ||  
            bpf_probe_read_kernel(&info.conn_key.src_ip.addr, sizeof(info.conn_key.src_ip.addr), &sk->__sk_common.skc_v6_rcv_saddr) != 0 ||
            bpf_probe_read_kernel(&info.conn_key.dest_ip.addr, sizeof(info.conn_key.dest_ip.addr), &sk->__sk_common.skc_v6_daddr) != 0)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_setup_ring_buff, sizeof(struct connection_setup_info), 0);
    if (!ringbuf_info) 
    {
        return 0;
    }   

    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_setup_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return 0;
}

SEC("fentry/tcp_fin")
int BPF_PROG(fentry_tcp_fin, struct sock *sk)
{
    struct connection_setup_info info;
    __builtin_memset(&info, 0, sizeof(info));
    info.timestamp = bpf_ktime_get_ns();
    info.proc = bpf_get_current_pid_tgid() >> 32;
    __u16 right_src_port = ((sk->__sk_common.skc_num >> 8) & 0xff) + ((sk->__sk_common.skc_num & 0xff) << 8);
    info.conn_key.src_port = right_src_port;
    info.conn_key.dest_port = sk->__sk_common.skc_dport;
    info.proto.l4_protocol = IPPROTO_TCP;
    info.ifindex = sk->__sk_common.skc_bound_dev_if;
    info.conn_flow = 0 + 1;
    // bpf_printk("tcp_connect end: sport: %x, dport: %x\n", info.conn_key.src_port, info.conn_key.dest_port);
    if (sk->__sk_common.skc_family == AF_INET)
    {
        info.conn_key.src_ip.version = IPV4;
        info.conn_key.dest_ip.version = IPV4;
        if (sk->__sk_common.skc_rcv_saddr == sk->__sk_common.skc_daddr ||  
            bpf_probe_read_kernel(&info.conn_key.src_ip.addr, sizeof(info.conn_key.src_ip.addr), &sk->__sk_common.skc_rcv_saddr) != 0 ||
            bpf_probe_read_kernel(&info.conn_key.dest_ip.addr, sizeof(info.conn_key.dest_ip.addr), &sk->__sk_common.skc_daddr) != 0)
        {
            return 0;
        }
    }
    else if (sk->__sk_common.skc_family == AF_INET6)
    {
        info.conn_key.src_ip.version = IPV6;
        info.conn_key.dest_ip.version = IPV6;
        if (sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8 == sk->__sk_common.skc_v6_daddr.in6_u.u6_addr8 ||  
            bpf_probe_read_kernel(&info.conn_key.src_ip.addr, sizeof(info.conn_key.src_ip.addr), &sk->__sk_common.skc_v6_rcv_saddr) != 0 ||
            bpf_probe_read_kernel(&info.conn_key.dest_ip.addr, sizeof(info.conn_key.dest_ip.addr), &sk->__sk_common.skc_v6_daddr) != 0)
        {
            return 0;
        }
    }
    else
    {
        return 0;
    }

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_setup_ring_buff, sizeof(struct connection_setup_info), 0);
    if (!ringbuf_info) 
    {
        return 0;
    }   
    
    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_setup_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return 0;
}

