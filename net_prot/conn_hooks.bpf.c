#include "vmlinux.h"
#include "conn_structs.bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TC_ACT_UNSPEC -1
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define ETH_P_IP	0x0800
#define AF_INET	2
#define ___constant_swab16(x) ((__u16)(				\
	(((__u16)(x) & (__u16)0x00ffU) << 8) |			\
	(((__u16)(x) & (__u16)0xff00U) >> 8)))
#define __constant_htons(x) ((__be16)___constant_swab16((x)))

static void print_buff(struct sk_buff* skb)
{
    if (skb == NULL)
        return;

    __u16 mac_header;
    if(bpf_probe_read_kernel(&mac_header, sizeof(mac_header), &skb->mac_header) != 0)
    {
        //bpf_printk("there is no mac header ???");
        return;
    }

    void *head;
    void *data;
    sk_buff_data_t tail;
    sk_buff_data_t end;
	unsigned int len;
	unsigned int data_len;
    if( bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0 ||
        bpf_probe_read_kernel(&data, sizeof(data), &skb->data) != 0 || 
        bpf_probe_read_kernel(&end, sizeof(end), &skb->end) != 0 || 
        bpf_probe_read_kernel(&len, sizeof(len), &skb->len) != 0 ||
        bpf_probe_read_kernel(&data_len, sizeof(data_len), &skb->data_len) != 0 ||
        bpf_probe_read_kernel(&tail, sizeof(tail), &skb->tail) != 0)
    {
        //bpf_printk("there is no pointers for skb");
        return;
    }
    else
    {
        //bpf_printk("print buff data head: %x, data %x, len: %d", head, data, len);
        //bpf_printk("print buff data tail: %d, end %d, data_len: %d", tail, end, data_len);
    }

    u8 buff[100];
    __builtin_memset(&buff, 1, sizeof(buff));
    if (len - data_len > 0)
    {
        if (bpf_probe_read_kernel(&buff, sizeof(buff), head) < 0)
            bpf_printk("print buff data: well there was an error getting the common data");

        //bpf_printk("print buff data 0: %x %x %x", buff[0], buff[1], buff[2]);
        //bpf_printk("print buff data 1: %x %x %x", buff[3], buff[4], buff[5]);
        //bpf_printk("print buff data 2: %x %x %x", buff[6], buff[7], buff[8]);
        //bpf_printk("print buff data 3: %x %x %x", buff[9], buff[10], buff[11]);
        //bpf_printk("print buff data 4: %x %x %x", buff[12], buff[13], buff[14]);
        //bpf_printk("print buff data 5: %x %x %x", buff[15], buff[16], buff[17]);
        //bpf_printk("print buff data 6: %x %x %x", buff[18], buff[19], buff[20]);
        //bpf_printk("print buff data 7: %x %x %x", buff[21], buff[22], buff[23]);
        //bpf_printk("print buff data 8: %x %x %x", buff[24], buff[25], buff[26]);
        //bpf_printk("print buff data 9: %x %x %x", buff[27], buff[28], buff[29]);
        //bpf_printk("print buff data 10: %x %x %x", buff[30], buff[31], buff[32]);
        //bpf_printk("print buff data 11: %x %x %x", buff[33], buff[34], buff[35]);
        //bpf_printk("print buff data 12: %x %x %x", buff[36], buff[37], buff[38]);
        //bpf_printk("print buff data 13: %x %x %x", buff[39], buff[40], buff[41]);
        //bpf_printk("print buff data 14: %x %x %x", buff[42], buff[43], buff[44]);
        //bpf_printk("print buff data 15: %x %x %x", buff[45], buff[46], buff[47]);
        //bpf_printk("print buff data 16: %x %x %x", buff[48], buff[49], buff[50]);
        //bpf_printk("print buff data 17: %x %x %x", buff[51], buff[52], buff[53]);
        //bpf_printk("print buff data 18: %x %x %x", buff[54], buff[55], buff[56]);
        //bpf_printk("print buff data 19: %x %x %x", buff[57], buff[58], buff[59]);
        //bpf_printk("print buff data 20: %x %x %x", buff[60], buff[61], buff[62]);
        //bpf_printk("print buff data 21: %x %x %x", buff[63], buff[64], buff[65]);
        //bpf_printk("print buff data 22: %x %x %x", buff[66], buff[67], buff[68]);
        //bpf_printk("print buff data 23: %x %x %x", buff[69], buff[70], buff[71]);
        //bpf_printk("print buff data 24: %x %x %x", buff[72], buff[73], buff[74]);
        //bpf_printk("print buff data 25: %x %x %x", buff[75], buff[76], buff[77]);
        //bpf_printk("print buff data 26: %x %x %x", buff[78], buff[79], buff[80]);
        //bpf_printk("print buff data 27: %x %x %x", buff[81], buff[82], buff[83]);
        //bpf_printk("print buff data 28: %x %x %x", buff[84], buff[85], buff[86]);
        //bpf_printk("print buff data 29: %x %x %x", buff[87], buff[88], buff[89]);
        //bpf_printk("print buff data 29: %x %x %x", buff[90], buff[91], buff[82]);

        // if (data_len > 0)
        // {
        //     struct skb_shared_info *shinfo = (struct skb_shared_info *)(head + end);
        //     __u8 nr_frags;
        //     bpf_probe_read_kernel(&nr_frags, sizeof(__u8), &shinfo->nr_frags);
        //     skb_frag_t frag[17];
        //     bpf_probe_read_kernel(&frag, sizeof(frag), &shinfo->frags);
        //     //bpf_printk("print buff data nr_frags: %d, frag, %x", nr_frags, frag);

        //     if (nr_frags > 0)
        //     {
        //         struct page* frag_data;
        //         bpf_probe_read_kernel(&frag_data, sizeof(frag_data), &frag[0].bv_page);
        //         unsigned int bv_offset;
        //         bpf_probe_read_kernel(&bv_offset, sizeof(unsigned int), &frag[0].bv_offset);
        //         frag_data = (void*)frag_data + bv_offset;
        //         unsigned int frag_len;
        //         bpf_probe_read_kernel(&frag_len, sizeof(unsigned int), &frag[0].bv_len);
        //         //bpf_printk("print buff data page: %x, offset: %d, len: %d", frag_data, bv_offset, frag_len);
        //         void* fin_mem;
        //         bpf_probe_read_kernel(&fin_mem, sizeof(fin_mem), &frag_data->s_mem); // how to read the page virtual address to get the data
        //         u8 frag_buff[6];
        //         __builtin_memset(&frag_buff, 1, sizeof(frag_buff));    
        //         bpf_probe_read_kernel(&frag_buff, sizeof(frag_buff), fin_mem);
        //         //bpf_printk("print buff data 0: %x %x %x", frag_buff[0], frag_buff[1], frag_buff[2]);
        //         //bpf_printk("print buff data 0: %x %x %x", frag_buff[3], frag_buff[4], frag_buff[5]);
        //     }
        // }
    }
}

static void get_buff_with_load(struct __sk_buff *ctx, __u8* ingress)
{
    if (ctx == NULL || ingress == NULL)
        return;

    __u32 len = (__u32)ctx->len;
    u32 buf_copy_size = (size_t)MAX_BUF_SIZE > len ? len : (size_t)MAX_BUF_SIZE;
    buf_copy_size &= 0xFFFFFFFF;
    long int ret = bpf_skb_pull_data(ctx, buf_copy_size);
    void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
    __u32 data_len = data_end - data;

    struct ethhdr *l2;
	struct iphdr *l3;

	if (ctx->protocol != __constant_htons(ETH_P_IP))
		return ;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return ;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return;

    u32 saddr;
    u32 daddr;
    u8 ip_protocol;
    if (bpf_probe_read_kernel(&saddr, sizeof(saddr), &l3->saddr) != 0 ||
        bpf_probe_read_kernel(&daddr, sizeof(daddr), &l3->daddr) != 0 ||
        bpf_probe_read_kernel(&ip_protocol, sizeof(ip_protocol), &l3->protocol) != 0)
    {
        // bpf_printk("get_buff_with_load %d bad ip values", ingress);
        return ;
    }

    __u16 src_port = 0;
    __u16 dest_port = 0;
    void* header_to_read = data;
    if (ip_protocol == IPPROTO_TCP) 
    {
        //bpf_printk("get_buff_with_load %d bad ip proto", ingress);
        struct tcphdr *tcp = (struct tcphdr *)(l3 + 1);
        if ((void *)(tcp + 1) > data_end)
        {
            // bpf_printk("get_buff_with_load %d bad tcp header", ingress);
            return ;
        }

        bpf_probe_read_kernel(&dest_port, sizeof(dest_port), &tcp->dest);
        bpf_probe_read_kernel(&src_port, sizeof(src_port), &tcp->source);
        header_to_read = tcp;
    }
    else if(ip_protocol == IPPROTO_UDP)
    {
        //bpf_printk("get_buff_with_load %d bad ip proto", ingress);
        struct udphdr *udp = (struct udphdr *)(l3 + 1);
        if ((void *)(udp + 1) > data_end)
        {
            // bpf_printk("get_buff_with_load %d bad udp header", ingress);
            return ;
        }

        bpf_probe_read_kernel(&dest_port, sizeof(dest_port), &udp->dest);
        bpf_probe_read_kernel(&src_port, sizeof(src_port), &udp->source);
        header_to_read = udp;
    }
    
    struct connection_config_key config_key;
    __builtin_memset(&config_key, 0, sizeof(config_key));
    config_key.local_ip = *ingress == 0 ? saddr : daddr;
    config_key.local_port = *ingress == 0 ? src_port : dest_port;
    config_key.remote_ip = *ingress != 0 ? saddr : daddr;
    config_key.remote_port = *ingress != 0 ? src_port : dest_port;

    

    // if (config_key.local_ip == 0x201fea9 || config_key.remote_ip == 0x201fea9)
    // {
    //     bpf_printk("print buff data: called ingress: %d", ingress);
    //     bpf_printk("print buff data: called ingress with data: %x, %x, %d", data, data_end, data_len);
    //     u8 buff[100];
    //     __builtin_memset(&buff, 1, sizeof(buff));
    //     if (bpf_probe_read_kernel(&buff, sizeof(buff), data) < 0)
    //         //bpf_printk("print buff data: well there was an error getting the common data");
    //     bpf_printk("print buff data 0: %x %x %x", buff[0], buff[1], buff[2]);
    //     bpf_printk("print buff data 1: %x %x %x", buff[3], buff[4], buff[5]);
    //     bpf_printk("print buff data 2: %x %x %x", buff[6], buff[7], buff[8]);
    //     bpf_printk("print buff data 3: %x %x %x", buff[9], buff[10], buff[11]);
    //     bpf_printk("print buff data 4: %x %x %x", buff[12], buff[13], buff[14]);
    //     bpf_printk("print buff data 5: %x %x %x", buff[15], buff[16], buff[17]);
    //     bpf_printk("print buff data 6: %x %x %x", buff[18], buff[19], buff[20]);
    //     bpf_printk("print buff data 7: %x %x %x", buff[21], buff[22], buff[23]);
    //     bpf_printk("print buff data 8: %x %x %x", buff[24], buff[25], buff[26]);
    //     bpf_printk("print buff data 9: %x %x %x", buff[27], buff[28], buff[29]);
    //     bpf_printk("print buff data 10: %x %x %x", buff[30], buff[31], buff[32]);
    //     bpf_printk("print buff data 11: %x %x %x", buff[33], buff[34], buff[35]);
    //     bpf_printk("print buff data 12: %x %x %x", buff[36], buff[37], buff[38]);
    //     bpf_printk("print buff data 13: %x %x %x", buff[39], buff[40], buff[41]);
    //     bpf_printk("print buff data 14: %x %x %x", buff[42], buff[43], buff[44]);
    //     bpf_printk("print buff data 15: %x %x %x", buff[45], buff[46], buff[47]);
    //     bpf_printk("print buff data 16: %x %x %x", buff[48], buff[49], buff[50]);
    //     bpf_printk("print buff data 17: %x %x %x", buff[51], buff[52], buff[53]);
    //     bpf_printk("print buff data 18: %x %x %x", buff[54], buff[55], buff[56]);
    //     bpf_printk("print buff data 19: %x %x %x", buff[57], buff[58], buff[59]);
    //     bpf_printk("print buff data 20: %x %x %x", buff[60], buff[61], buff[62]);
    //     bpf_printk("print buff data 21: %x %x %x", buff[63], buff[64], buff[65]);
    //     bpf_printk("print buff data 22: %x %x %x", buff[66], buff[67], buff[68]);
    //     bpf_printk("print buff data 23: %x %x %x", buff[69], buff[70], buff[71]);
    //     bpf_printk("print buff data 24: %x %x %x", buff[72], buff[73], buff[74]);
    //     bpf_printk("print buff data 25: %x %x %x", buff[75], buff[76], buff[77]);
    //     bpf_printk("print buff data 26: %x %x %x", buff[78], buff[79], buff[80]);
    //     bpf_printk("print buff data 27: %x %x %x", buff[81], buff[82], buff[83]);
    //     bpf_printk("print buff data 28: %x %x %x", buff[84], buff[85], buff[86]);
    //     bpf_printk("print buff data 29: %x %x %x", buff[87], buff[88], buff[89]);
    //     bpf_printk("print buff data 29: %x %x %x", buff[90], buff[91], buff[92]);
    //     bpf_printk("print buff data 29: %x %x %x", buff[93], buff[94], buff[95]);
    // }


    struct connection_config_value* config_value = (struct connection_config_value*)bpf_map_lookup_elem(&connection_config, &config_key);
    if (!(config_value != NULL && (*ingress == 1 || config_value->stop_egress_pkt_data != 0) && (*ingress == 0 || config_value->stop_ingress_pkt_data != 0)))
    {
        struct connection_kern_data* ring_info = bpf_ringbuf_reserve(&pkt_data_ring_buff, sizeof(struct connection_kern_data), 0);
        if (!ring_info) 
        {
            return;
        }
        bpf_probe_read_kernel(&ring_info->buf, buf_copy_size, header_to_read);
        ring_info->conn_key.local_ip = config_key.local_ip;
        ring_info->conn_key.local_port = config_key.local_port;
        ring_info->conn_key.remote_ip = config_key.remote_ip;
        ring_info->conn_key.remote_port = config_key.remote_port;
        ring_info->ingress = *ingress;
        ring_info->pk_len = buf_copy_size;

        // if (config_key.local_ip == 0x201fea9 || config_key.remote_ip == 0x201fea9)
        // {
        //     bpf_printk("config values: %d, %d, %d", config_key.local_ip, config_key.remote_ip, config_key.local_port);
        //     bpf_printk("config values: %d, %d, %d", config_key.remote_port, ring_info->conn_key.local_port, ring_info->conn_key.remote_port);
        // }
        bpf_ringbuf_submit(ring_info, 0);
    }

}


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
        //bpf_printk("there is no mac header ???");
        return NULL;
    }

    //bpf_printk("head: %x, end: %d, mac_header: %d", head, end, mac_header);
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
        return;

    void* head;
    sk_buff_data_t end;
    if(bpf_probe_read_kernel(&end, sizeof(end), &skb->end) != 0 ||
        (bpf_probe_read_kernel(&head, sizeof(head), &skb->head) != 0))
    {
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
        return;
    }

    u16 h_proto;
    if (bpf_probe_read_kernel(&h_proto, sizeof(h_proto), &eth->h_proto) == 0)
    {
        if (h_proto != __constant_htons(ETH_P_IP))
        {
            return;  //only support IPv4
        }
    }
    ret->l3_proto = __constant_htons(ETH_P_IP);

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > head + end)
    {
        return;
    }
    bpf_probe_read_kernel(&ret->pk_len, sizeof(ret->pk_len), &skb->len);

    if (bpf_probe_read_kernel(&ret->saddr, sizeof(ret->saddr), &ip->saddr) != 0 ||
        bpf_probe_read_kernel(&ret->daddr, sizeof(ret->daddr), &ip->daddr) != 0 ||
        bpf_probe_read_kernel(&ret->l4_proto, sizeof(ret->l4_proto), &ip->protocol) != 0)
    {
        return;
    }

    if (ret->saddr == ret->daddr)
    {
        return; // removing loopback traffic
    }

    if (ret->l4_proto == IPPROTO_TCP) 
    {
        struct tcphdr *tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > head + end)
        {
            return;
        }

        bpf_probe_read_kernel(&ret->dport, sizeof(ret->dport), &tcp->dest);
        bpf_probe_read_kernel(&ret->sport, sizeof(ret->sport), &tcp->source);
        //bpf_printk("TCP Connection for egress");
        //bpf_printk("src_ip: %x.%d", info->conn_key.src_ip, info->conn_key.src_port);
        //bpf_printk("dest_ip: %x.%d", info->conn_key.dest_ip, info->conn_key.dest_port);
    }
    else if (ret->l4_proto == IPPROTO_UDP) 
    {
        struct udphdr *udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > head + end)
        {          
            return;
        }
        
        bpf_probe_read_kernel(&ret->dport, sizeof(ret->dport), &udp->dest);
        bpf_probe_read_kernel(&ret->sport, sizeof(ret->sport), &udp->source);
        //bpf_printk("UDP Connection for egress");
        //bpf_printk("src_ip: %x:%d", info->conn_key.src_ip, info->conn_key.src_port);
        //bpf_printk("dest_ip: %x:%d", info->conn_key.dest_ip, info->conn_key.dest_port);
    }  
    else
    {
        ret->sport = -1;
        ret->dport = -1;
        //bpf_printk("Other Connection for egress src_ip: %x, dest_ip: %x", info->conn_key.src_ip, info->conn_key.dest_ip);
    }

    ret->valid = 1;
    return;
}


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


    // if (info.conn_key.src_ip == 0x201fea9 || info.conn_key.dest_ip == 0x201fea9)
    // {
    //     bpf_printk("config values egress con: %d, %d, %d", info.conn_key.src_ip, info.conn_key.dest_ip, info.conn_key.src_port);
    //     bpf_printk("config values egress con: %d", info.conn_key.dest_port);
    // }
    
    struct pkt_info* ring_info = bpf_ringbuf_reserve(&pkt_info_ring_buff, sizeof(struct pkt_info), 0);
    if (!ring_info) 
    {
        return 0;
    }  
    copy_to_ring(ring_info, &info);

    //bpf_printk("Pushing in the ring buff from __dev_queue_xmit");
    bpf_ringbuf_submit(ring_info, 0);
    return 0;
}

SEC("kprobe/__netif_receive_skb_core")
int kprobe_netif_receive_skb(struct pt_regs *ctx)
{
    __u8 ingress = 1;
    struct sk_buff *skb;
    if (bpf_probe_read_kernel(&skb, sizeof(skb), (void *)PT_REGS_PARM1(ctx)) != 0)
    {
        //bpf_printk("kprobe: __netif_receive_skb unable to get sk_buff");
        return 0;
    }

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
    
    // if (info.conn_key.src_ip == 0x201fea9 || info.conn_key.dest_ip == 0x201fea9)
    // {
    //     bpf_printk("config values ingress con: %d, %d, %d", info.conn_key.src_ip, info.conn_key.dest_ip, info.conn_key.src_port);
    //     bpf_printk("config values ingress con: %d", info.conn_key.dest_port);
    // }

    struct pkt_info* ring_info = bpf_ringbuf_reserve(&pkt_info_ring_buff, sizeof(struct pkt_info), 0);
    if (!ring_info) 
    {
        return 0;
    }  
    copy_to_ring(ring_info, &info);

    // bpf_printk("Pushing in the ring buff from __dev_queue_xmit");
    bpf_ringbuf_submit(ring_info, 0);
    return 0;
}

SEC("fentry/tcp_connect")
int BPF_PROG(fentry_tcp_connect, struct sock *sk)
{
    struct connection_setup_info info;
    __builtin_memset(&info, 0, sizeof(info));
    info.timestamp = bpf_ktime_get_ns();
    info.proc = bpf_get_current_pid_tgid() >> 32;
    info.conn_key.src_ip = sk->__sk_common.skc_rcv_saddr; 
    __u16 right_src_port = ((sk->__sk_common.skc_num >> 8) & 0xff) + ((sk->__sk_common.skc_num & 0xff) << 8);
    info.conn_key.src_port = right_src_port;
    info.conn_key.dest_ip = sk->__sk_common.skc_daddr;
    info.conn_key.dest_port = sk->__sk_common.skc_dport;
    info.proto.l4_protocol = IPPROTO_TCP;
    info.ifindex = sk->__sk_common.skc_bound_dev_if;
    info.conn_flow = (1<<1) + 0;

    if (info.conn_key.src_ip == info.conn_key.dest_ip)
    {
        return 0; // removing loopback traffic
    }

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_setup_ring_buff, sizeof(struct connection_setup_info), 0);
    if (!ringbuf_info) 
    {
        return 0;
    }   
    //bpf_printk("[testing]connection_data tcp_connect Pushing in the ring buff %x, %x", info.conn_key.src_ip, info.conn_key.dest_ip);

    // if (info.conn_key.src_ip == 0x201fea9 || info.conn_key.dest_ip == 0x201fea9)
    // {
    //     bpf_printk("config values con con: %d, %d, %d", info.conn_key.src_ip, info.conn_key.dest_ip, info.conn_key.src_port);
    //     bpf_printk("config values con con: %d", info.conn_key.dest_port);
    // }

    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_setup_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return 0;
}


SEC("fentry/tcp_conn_request")
int BPF_PROG(fentry_tcp_conn_request, struct request_sock_ops *rsk_ops,
		     const struct tcp_request_sock_ops *af_ops,
		     struct sock *sk, struct sk_buff *skb)
{
    //bpf_printk("[testing]connection_data tcp_conn_request");
    // print_buff(skb);

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

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_setup_ring_buff, sizeof(struct connection_setup_info), 0);
    if (!ringbuf_info) 
    {
        //bpf_printk("tcp_conn_request bad ringbuff");
        return 0;
    }   
    //bpf_printk("[testing]connection_data tcp_conn_request Pushing in the ring buff %x, %x", info.conn_key.src_ip, info.conn_key.dest_ip);

    // if (info.conn_key.src_ip == 0x201fea9 || info.conn_key.dest_ip == 0x201fea9)
    // {
    //     bpf_printk("config values rew con: %d, %d, %d", info.conn_key.src_ip, info.conn_key.dest_ip, info.conn_key.src_port);
    //     bpf_printk("config values rew con: %d", info.conn_key.dest_port);
    // }

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
    info.conn_key.src_ip = sk->__sk_common.skc_rcv_saddr; 
    info.conn_key.src_port = sk->__sk_common.skc_num;
    info.conn_key.dest_ip = sk->__sk_common.skc_daddr;
    info.conn_key.dest_port = sk->__sk_common.skc_dport;
    info.proto.l4_protocol = IPPROTO_TCP;
    info.ifindex = sk->__sk_common.skc_bound_dev_if;
    info.conn_flow = 0 + 0;

    if (info.conn_key.src_ip == info.conn_key.dest_ip)
    {
        return 0; // removing loopback traffic
    }

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_setup_ring_buff, sizeof(struct connection_setup_info), 0);
    if (!ringbuf_info) 
    {
        return 0;
    }   
    //bpf_printk("[testing]connection_data fentry_tcp_close Pushing in the ring buff %x, %x", info.conn_key.src_ip, info.conn_key.dest_ip);

    // if (info.conn_key.src_ip == 0x201fea9 || info.conn_key.dest_ip == 0x201fea9)
    // {
    //     bpf_printk("config values close con: %d, %d, %d", info.conn_key.src_ip, info.conn_key.dest_ip, info.conn_key.src_port);
    //     bpf_printk("config values close con: %d", info.conn_key.dest_port);
    // }

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
    info.conn_key.src_ip = sk->__sk_common.skc_rcv_saddr; 
    __u16 right_src_port = ((sk->__sk_common.skc_num >> 8) & 0xff) + ((sk->__sk_common.skc_num & 0xff) << 8);
    info.conn_key.src_port = right_src_port;
    info.conn_key.dest_ip = sk->__sk_common.skc_daddr;
    info.conn_key.dest_port = sk->__sk_common.skc_dport;
    info.proto.l4_protocol = IPPROTO_TCP;
    info.ifindex = sk->__sk_common.skc_bound_dev_if;
    info.conn_flow = 0 + 1;

    if (info.conn_key.src_ip == info.conn_key.dest_ip)
    {
        return 0; // removing loopback traffic
    }

    struct connection_creation_info *ringbuf_info;
    ringbuf_info = bpf_ringbuf_reserve(&connection_setup_ring_buff, sizeof(struct connection_setup_info), 0);
    if (!ringbuf_info) 
    {
        return 0;
    }   
    //bpf_printk("[testing]connection_data tcp_fin Pushing in the ring buff %x, %x", info.conn_key.src_ip, info.conn_key.dest_ip);

    // if (info.conn_key.src_ip == 0x201fea9 || info.conn_key.dest_ip == 0x201fea9)
    // {
    //     bpf_printk("config values fin con: %d, %d, %d", info.conn_key.src_ip, info.conn_key.dest_ip, info.conn_key.src_port);
    //     bpf_printk("config values fin con: %d", info.conn_key.dest_port);
    // }

    __builtin_memcpy(ringbuf_info, &info, sizeof(struct connection_setup_info));
    bpf_ringbuf_submit(ringbuf_info, 0);

    return 0;
}

SEC("tc")
int tc_ingress(struct __sk_buff *ctx) 
{
    __u8 ingress = 1;
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;

	if (ctx->protocol != __constant_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_UNSPEC;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_UNSPEC;

    u32 saddr;
    u32 daddr;
    if (bpf_probe_read_kernel(&saddr, sizeof(saddr), &l3->saddr) != 0 ||
        bpf_probe_read_kernel(&daddr, sizeof(daddr), &l3->daddr) != 0)
    {
        // bpf_printk("get_buff_with_load %d bad ip values", ingress);
        return TC_ACT_UNSPEC;
    }
    
    __u32* blocked_ip = (__u32*)bpf_map_lookup_elem(&blocked_ips, &saddr);
    if (blocked_ip != NULL)
        return TC_ACT_SHOT;

    blocked_ip = (__u32*)bpf_map_lookup_elem(&blocked_ips, &daddr);
    if (blocked_ip != NULL)
        return TC_ACT_SHOT;
    
	// bpf_printk("Got IP packet ingress: src_ip: %x, dest_ip: %x", l3->saddr, l3->daddr);
    get_buff_with_load(ctx, &ingress);

	return TC_ACT_UNSPEC;
}

SEC("tc")
int tc_egress(struct __sk_buff *ctx) 
{
    __u8 ingress = 0;
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	struct iphdr *l3;

	if (ctx->protocol != __constant_htons(ETH_P_IP))
		return TC_ACT_UNSPEC;

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_UNSPEC;

	l3 = (struct iphdr *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_UNSPEC;

    u32 saddr;
    u32 daddr;
    if (bpf_probe_read_kernel(&saddr, sizeof(saddr), &l3->saddr) != 0 ||
        bpf_probe_read_kernel(&daddr, sizeof(daddr), &l3->daddr) != 0)
    {
        // bpf_printk("get_buff_with_load %d bad ip values", ingress);
        return TC_ACT_UNSPEC;
    }

    __u32* blocked_ip = (__u32*)bpf_map_lookup_elem(&blocked_ips, &saddr);
    if (blocked_ip != NULL)
        return TC_ACT_SHOT;

    blocked_ip = (__u32*)bpf_map_lookup_elem(&blocked_ips, &daddr);
    if (blocked_ip != NULL)
        return TC_ACT_SHOT;

	// bpf_printk("Got IP packet egress: src_ip: %x, dest_ip: %x", l3->saddr, l3->daddr);
    get_buff_with_load(ctx, &ingress);

	return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
