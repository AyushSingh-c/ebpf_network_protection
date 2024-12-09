#include "src/kern_code/common_skb_reader.h"


SEC("tracepoint/net/netif_receive_skb")
int trace_netif_receive_skb(struct trace_event_raw_netif_receive_skb *ctx)
{
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;

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

