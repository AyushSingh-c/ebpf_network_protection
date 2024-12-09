#include "src/kern_code/debug.bpf.h"

#include "src/vmlinux.h"
#include "src/conn_structs.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAC_SRC_OFF (offsetof(struct ethhdr, h_source))
#define MAC_DEST_OFF (offsetof(struct ethhdr, h_dest))

#define IP_V4_CSUM_OFF (sizeof(struct ethhdr) + offsetof(struct iphdr, check))
#define IP_V4_SRC_OFF (sizeof(struct ethhdr) + offsetof(struct iphdr, saddr))
#define IP_V6_SRC_OFF (sizeof(struct ethhdr) + offsetof(struct ipv6hdr, saddr))
#define IP_V4_DST_OFF (sizeof(struct ethhdr) + offsetof(struct iphdr, daddr))
#define IP_V6_DST_OFF (sizeof(struct ethhdr) + offsetof(struct ipv6hdr, saddr))
#define TCP_V4_CSUM_OFF (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, check))
#define TCP_V6_CSUM_OFF (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, check))
#define TCP_V4_SPORT_OFF (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, source))
#define TCP_V6_SPORT_OFF (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, source))
#define TCP_V4_DPORT_OFF (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define TCP_V6_DPORT_OFF (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct tcphdr, dest))
#define UDP_V4_CSUM_OFF (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, check))
#define UDP_V6_CSUM_OFF (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct udphdr, check))
#define UDP_V4_SPORT_OFF (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, source))
#define UDP_V6_SPORT_OFF (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct udphdr, source))
#define UDP_V4_DPORT_OFF (sizeof(struct ethhdr) + sizeof(struct iphdr) + offsetof(struct udphdr, dest))
#define UDP_V6_DPORT_OFF (sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + offsetof(struct udphdr, dest))
#define TOS_V4_OFF (sizeof(struct ethhdr) + offsetof(struct iphdr, tos))
#define TOS_V6_OFF (sizeof(struct ethhdr) + offsetof(struct ipv6hdr, priority))
#define IS_PSEUDO 0x10
#define PACKET_HOST 0

static inline void cksum_ip_addr(ip_address_t* ip, __u32* checksum)
{
    if (ip == NULL || checksum == NULL)
    {
        bpf_printk("cksum_ip_addr: invalid arguments");
        return;
    }
    (*checksum) = 0;
    if (ip->version == IPV4)
    {
        for (int i = 0; i+1 < IPV4_ADDR_LEN; i+=2)
        {
            (*checksum) += ip->addr.ipv4[i];
            (*checksum) += ip->addr.ipv4[i+1] << 8;
        }
    }
    else
    {
        for (int i = 0; i < IPV6_ADDR_LEN; i++)
        {
            (*checksum) += ip->addr.ipv6[i];
        }
    }
    int max_loop = ((ip->version == IPV4) ? IPV4_ADDR_LEN : IPV6_ADDR_LEN) + 1;
    while (((*checksum) >> 16) && (max_loop>0))
    {
        (*checksum) = ((*checksum) & 0xFFFF) + ((*checksum) >> 16);
        max_loop--;
    }
    return;
}

static inline void set_tcp_ip_src(struct __sk_buff *skb, ip_address_t* old_ip, ip_address_t* new_ip)
{
    __u32 check_diff = 0, temp = 0;
    cksum_ip_addr(old_ip, &temp);
    check_diff+=(~temp) & 0xFFFF;
    cksum_ip_addr(new_ip, &temp);
    check_diff+=temp;
    if (check_diff >> 16)
    {
        check_diff = (check_diff & 0xFFFF) + (check_diff >> 16);
    }
    if (old_ip->version == IPV4)
    {
        bpf_l4_csum_replace(skb, TCP_V4_CSUM_OFF, 0, check_diff, IS_PSEUDO);
        bpf_l3_csum_replace(skb, IP_V4_CSUM_OFF, 0, check_diff, 0);
        bpf_skb_store_bytes(skb, IP_V4_SRC_OFF, &new_ip->addr.ipv4, sizeof(new_ip->addr.ipv4), 0);
    }
    else
    {
        bpf_l4_csum_replace(skb, TCP_V6_CSUM_OFF, 0, check_diff, IS_PSEUDO);
        bpf_skb_store_bytes(skb, IP_V6_SRC_OFF, &new_ip->addr.ipv6, sizeof(new_ip->addr.ipv6), 0);
    }
}

static inline void set_tcp_ip_dest(struct __sk_buff *skb, ip_address_t* old_ip, ip_address_t* new_ip)
{
    __u32 check_diff = 0, temp = 0;
    cksum_ip_addr(old_ip, &temp);
    check_diff+=(~temp) & 0xFFFF;
    cksum_ip_addr(new_ip, &temp);
    check_diff+=temp;
    if (check_diff >> 16)
    {
        check_diff = (check_diff & 0xFFFF) + (check_diff >> 16);
    }

    if (old_ip->version == IPV4)
    {
        bpf_l4_csum_replace(skb, TCP_V4_CSUM_OFF, 0, check_diff, IS_PSEUDO | sizeof(check_diff));
        bpf_l3_csum_replace(skb, IP_V4_CSUM_OFF, 0, check_diff, sizeof(check_diff));
        bpf_skb_store_bytes(skb, IP_V4_DST_OFF, &new_ip->addr.ipv4, sizeof(new_ip->addr.ipv4), 0);
    }
    else
    {
        bpf_l4_csum_replace(skb, TCP_V6_CSUM_OFF, 0, check_diff, IS_PSEUDO);
        bpf_skb_store_bytes(skb, IP_V6_DST_OFF, &new_ip->addr.ipv6, sizeof(new_ip->addr.ipv6), 0);
    }
}

static inline void set_tcp_port_src(struct __sk_buff *skb, __u16 old_port, __u16 new_port)
{
	bpf_l4_csum_replace(skb, TCP_V4_CSUM_OFF, old_port, new_port, sizeof(new_port));
    bpf_skb_store_bytes(skb, TCP_V4_SPORT_OFF, &new_port, sizeof(new_port), 0);
}

static inline void set_tcp_port_dest(struct __sk_buff *skb, __u16 old_port, __u16 new_port)
{
	bpf_l4_csum_replace(skb, TCP_V4_CSUM_OFF, old_port, new_port, sizeof(new_port));
    bpf_skb_store_bytes(skb, TCP_V4_DPORT_OFF, &new_port, sizeof(new_port), 0);
}

static inline void set_udp_ip_src(struct __sk_buff *skb, ip_address_t* old_ip, ip_address_t* new_ip)
{
    __u32 check_diff = 0, temp = 0;
    cksum_ip_addr(old_ip, &temp);
    check_diff+=(~temp) & 0xFFFF;
    cksum_ip_addr(new_ip, &temp);
    check_diff+=temp;
    if (check_diff >> 16)
    {
        check_diff = (check_diff & 0xFFFF) + (check_diff >> 16);
    }
    if (old_ip->version == IPV4)
    {
        bpf_l4_csum_replace(skb, UDP_V4_CSUM_OFF, 0, check_diff, IS_PSEUDO);
        bpf_l3_csum_replace(skb, IP_V4_CSUM_OFF, 0, check_diff, 0);
        bpf_skb_store_bytes(skb, IP_V4_SRC_OFF, &new_ip->addr, sizeof(new_ip->addr), 0);
    }
    else
    {
        bpf_l4_csum_replace(skb, UDP_V6_CSUM_OFF, 0, check_diff, IS_PSEUDO);
        bpf_skb_store_bytes(skb, IP_V6_SRC_OFF, &new_ip->addr, sizeof(new_ip->addr), 0);
    }
}

static inline void set_udp_ip_dest(struct __sk_buff *skb, ip_address_t* old_ip, ip_address_t* new_ip)
{
    __u32 check_diff = 0, temp = 0;
    cksum_ip_addr(old_ip, &temp);
    check_diff+=(~temp) & 0xFFFF;
    cksum_ip_addr(new_ip, &temp);
    check_diff+=temp;
    if (check_diff >> 16)
    {
        check_diff = (check_diff & 0xFFFF) + (check_diff >> 16);
    }
    if (old_ip->version == IPV4)
    {
        bpf_l4_csum_replace(skb, UDP_V4_CSUM_OFF, 0, check_diff, IS_PSEUDO);
        bpf_l3_csum_replace(skb, IP_V4_CSUM_OFF, 0, check_diff, 0);
        bpf_skb_store_bytes(skb, IP_V4_DST_OFF, &new_ip->addr, sizeof(new_ip->addr), 0);
    }
    else
    {
        bpf_l4_csum_replace(skb, UDP_V6_CSUM_OFF, 0, check_diff, IS_PSEUDO);
        bpf_skb_store_bytes(skb, IP_V6_DST_OFF, &new_ip->addr, sizeof(new_ip->addr), 0);
    }
}

static inline void set_udp_port_src(struct __sk_buff *skb, __u16 old_port, __u16 new_port)
{
	bpf_l4_csum_replace(skb, UDP_V4_CSUM_OFF, old_port, new_port, sizeof(new_port));
    bpf_skb_store_bytes(skb, UDP_V4_SPORT_OFF, &new_port, sizeof(new_port), 0);
}

static inline void set_udp_port_dest(struct __sk_buff *skb, __u16 old_port, __u16 new_port)
{
	bpf_l4_csum_replace(skb, UDP_V4_CSUM_OFF, old_port, new_port, sizeof(new_port));
    bpf_skb_store_bytes(skb, UDP_V4_DPORT_OFF, &new_port, sizeof(new_port), 0);
}


__attribute__((always_inline))
static int send_data_to_rb(struct __sk_buff* ctx, struct connection_config_key* key, struct from_sk_buff *ret, __u8* ingress)
{
    if (ctx == NULL || key == NULL || ret == NULL || ingress == NULL)
    {
        bpf_printk("send_data_to_rb: invalid arguments");
        return -1;
    }

    void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;

    __u32 len = (__u32)ctx->len;
    u32 buf_copy_size = (size_t)MAX_BUF_SIZE > len ? len : (size_t)MAX_BUF_SIZE;
    buf_copy_size &= 0xFFFFFFFF;
    long int ret_code = bpf_skb_pull_data(ctx, buf_copy_size);

    struct connection_config_value config_val_temp;
    __builtin_memset(&config_val_temp, 0, sizeof(struct connection_config_value));
    struct connection_config_value* config_value = (struct connection_config_value*)bpf_map_lookup_elem(&connection_config, key);
    if (config_value == NULL || ((*ingress) == 1 && config_value->stop_ingress_pkt_data == 0) || ((*ingress) == 0 && config_value->stop_egress_pkt_data == 0))
    {
        if (config_value == NULL)
            bpf_map_update_elem(&connection_config, key, &config_val_temp, BPF_ANY);
        struct connection_kern_data* ring_info = bpf_ringbuf_reserve(&pkt_data_ring_buff, sizeof(struct connection_kern_data), 0);
        if (!ring_info) 
        {
            bpf_printk("send_data_to_rb: unable to get ring buffer");
            return -1;
        }
        bpf_probe_read_kernel(&ring_info->buf, buf_copy_size, data);
        ring_info->timestamp = bpf_ktime_get_ns();
        ring_info->conn_key = *key;
        ring_info->ingress = (*ingress);
        ring_info->pk_len = buf_copy_size;
        ring_info->proto.l4_protocol = ret->l4_proto;
        bpf_ringbuf_submit(ring_info, 0);
        return 0;
    }  
    // bpf_printk("send_data_to_rb: bad config value ingress: %d, stop_ingress_pkt_data: %d, stop_egress_pkt_data: %d", *ingress, config_value->stop_ingress_pkt_data, config_value->stop_egress_pkt_data);
    return 1;  
}

__attribute__((always_inline))
static int get_sk_info(struct __sk_buff *ctx, struct from_sk_buff *ret)
{
    if (ret == NULL || ctx == NULL)
    {
        bpf_printk("get_sk_info: invalid arguments");
        return -1;
    }

    void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2;
	if (ctx->protocol != __constant_htons(ETH_P_IP) && ctx->protocol != __constant_htons(ETH_P_IPV6))
    {
        // bpf_printk("get_sk_info: invalid protocol: %d", ctx->protocol);
		return -1; 
    }

	l2 = data;
	if ((void *)(l2 + 1) > data_end)
    {
        bpf_printk("get_sk_info: invalid data pointer");
		return -1;
    }

    ip_address_t saddr;
    __builtin_memset(&saddr, 0, sizeof(saddr));
    ip_address_t daddr;
    __builtin_memset(&daddr, 0, sizeof(daddr));
    void* after_ip;
    u8 ip_protocol; 

    if (ctx->protocol == __constant_htons(ETH_P_IP)) // for ipv4
    {
        struct iphdr *l3 = (struct iphdr *)(l2 + 1);
        if ((void *)(l3 + 1) > data_end)
        {
            bpf_printk("get_sk_info: invalid ip pointer");
            return -1;
        }
        
        saddr.version = IPV4;
        daddr.version = IPV4;

        if (bpf_probe_read_kernel(&saddr.addr, sizeof(__be32), &l3->saddr) != 0 ||
            bpf_probe_read_kernel(&daddr.addr, sizeof(__be32), &l3->daddr) != 0 ||
            bpf_probe_read_kernel(&ip_protocol, sizeof(ip_protocol), &l3->protocol) != 0)
        {
            bpf_printk("get_sk_info: unable to read ip header");
            return -1;
        }
        // fib_params.ipv4_src = l3->saddr; // Source IP address
        // fib_params.ipv4_dst = l3->daddr; // Destination IP address
        ret->l3_proto = IPV4;
        after_ip = (void*)(l3 + 1);
    }
    else if (ctx->protocol == __constant_htons(ETH_P_IPV6)) // for ipv6
    {
        struct ipv6hdr *l3_v6 = (struct ipv6hdr *)(l2 + 1);
        if ((void *)(l3_v6 + 1) > data_end)
        {
            bpf_printk("get_sk_info: invalid ipv6 pointer");
            return -1;
        }

        saddr.version = IPV6;
        daddr.version = IPV6;

        if (bpf_probe_read_kernel(&saddr.addr, sizeof(saddr.addr), &l3_v6->saddr) != 0 ||
            bpf_probe_read_kernel(&daddr.addr, sizeof(daddr.addr), &l3_v6->daddr) != 0 ||
            bpf_probe_read_kernel(&ip_protocol, sizeof(ip_protocol), &l3_v6->nexthdr) != 0)
        {
            bpf_printk("get_sk_info: unable to read ipv6 pointer");
            return -1;
        }
        // __builtin_memcpy(fib_params.ipv6_src, &l3_v6->saddr, sizeof(fib_params.ipv6_src));
        // __builtin_memcpy(fib_params.ipv6_dst, &l3_v6->daddr, sizeof(fib_params.ipv6_dst));
        ret->l3_proto = IPV6;
        after_ip = (void*)(l3_v6 + 1);
    }
    else
    {
        bpf_printk("get_sk_info: invalid l3 protocol");
        return -1;
    }
    
    __u16 src_port = 0;
    __u16 dest_port = 0;
    if (ip_protocol == IPPROTO_TCP) 
    {
        struct tcphdr *tcp = (struct tcphdr *)(after_ip);
        if ((void *)(tcp + 1) > data_end)
        {
            bpf_printk("get_sk_info: invalid tcp pointer");
            return -1;
        }

        bpf_probe_read_kernel(&dest_port, sizeof(dest_port), &tcp->dest);
        bpf_probe_read_kernel(&src_port, sizeof(src_port), &tcp->source);
    }
    else if(ip_protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = (struct udphdr *)(after_ip);
        if ((void *)(udp + 1) > data_end)
        {
            bpf_printk("get_sk_info: invalid udp pointer");
            return -1;
        }

        bpf_probe_read_kernel(&dest_port, sizeof(dest_port), &udp->dest);
        bpf_probe_read_kernel(&src_port, sizeof(src_port), &udp->source);
    }

    ret->saddr = saddr;
    ret->daddr = daddr;
    ret->sport = src_port;
    ret->dport = dest_port;
    ret->l4_proto = ip_protocol;
    ret->valid = 1;
    return 0;
}
    

SEC("tc")
int tc_ingress(struct __sk_buff *ctx) 
{
    if (ctx == NULL)
    {
        bpf_printk("invalid context for ingress traffic");
        return TC_ACT_UNSPEC;
    }

    __u8 ingress = 1;
	struct from_sk_buff ret;
    __builtin_memset(&ret, 0, sizeof(ret));
    if (get_sk_info(ctx, &ret) != 0)
    {
        // bpf_printk("unable to get sk info for ingress traffic %d", ctx->protocol);
        return TC_ACT_UNSPEC;
    }


    void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2 = (struct ethhdr *)data;
	if ((void *)(l2 + 1) > data_end)
    {
        bpf_printk("get_sk_info: invalid data pointer");
		return TC_ACT_UNSPEC;
    }

    struct ip_lpm_key lpm_key = {128, ret.saddr};
    __u8* redirect_ip = (__u8*)bpf_map_lookup_elem(&redirect_ips, &lpm_key);
    if (redirect_ip == NULL)
    {
        struct connection_config_key config_key;
        __builtin_memset(&config_key, 0, sizeof(config_key));
        config_key.local_ip =  ret.daddr;
        config_key.local_port = ret.dport;
        config_key.remote_ip = ret.saddr;
        config_key.remote_port = ret.sport;

        if (send_data_to_rb(ctx, &config_key, &ret, &ingress) == 0)
        {
            // bpf_printk("ingress sending data for src port: %d, dest port: %d\n", ret.sport, ret.dport);
        }

        __u8* blocked_ip = (__u8*)bpf_map_lookup_elem(&blocked_ips, &lpm_key);
        if (blocked_ip != NULL)
        {
            bpf_printk("blocking ip for ingress traffic");
            return TC_ACT_SHOT;
        }

        __u8* blocked_port = (__u8*)bpf_map_lookup_elem(&blocked_ports, &ret.dport);
        if (blocked_port != NULL)
        {
            bpf_printk("blocking port for ingress traffic");
            return TC_ACT_SHOT;
        }

        __u32 key = 0; // Index 0
        struct net_prot_config *value;
        value = bpf_map_lookup_elem(&config_map, &key);
        if (value == NULL)
        {
            bpf_printk("isolation config not there with tc_ingress");
            return TC_ACT_UNSPEC; // no config value is available
        }
        if (value->isolation)
        {
            struct network_tuple current_network_tuple = {ret.daddr, ret.dport, ret.saddr, ret.sport, ret.l4_proto};
            __u8 *value1 = (__u8 *)bpf_map_lookup_elem(&isolation_network_tuple, &current_network_tuple);
            __builtin_memset(&current_network_tuple.local_ip, 0, sizeof(ip_address_t));
            __u8 *value2 = (__u8 *)bpf_map_lookup_elem(&isolation_network_tuple, &current_network_tuple);
            if (value1 == NULL && value2 == NULL) 
            {
                bpf_printk("Permission denied for local port for tc_ingress =%d", ret.dport);
                return TC_ACT_SHOT; // Permission denied
            }
        }

        return TC_ACT_UNSPEC;
    }
    
    __u32 curr_ifindex = ctx->ifindex;
    struct redirection_endpoint_mac end_pt;
    struct redirection_endpoint end_pt_key;
    __builtin_memset(&end_pt, 0, sizeof(end_pt));
    __builtin_memset(&end_pt_key, 0, sizeof(end_pt_key));
    end_pt.interface_index = curr_ifindex;
    for (int i = 0; i < 6; i++)
    {
        end_pt.mac_addr[i] = l2->h_dest[i];
    }
    end_pt_key.port = ret.dport;
    end_pt_key.ip = ret.daddr;
    end_pt.endpoint = end_pt_key;
    struct redirection_endpoint_mac* next_end_pt = (struct redirection_endpoint_mac*)bpf_map_lookup_elem(&redirect_endpoints, &end_pt_key);
    if (next_end_pt == NULL)
    {
        struct redirection_endpoint_mac* honey_end_pt = (struct redirection_endpoint_mac*)bpf_map_lookup_elem(&reverse_redirect_endpoints, &end_pt_key);
        if (honey_end_pt != NULL)
        {
            // bpf_printk("ingress traffic on the honey pot interface %d\n", curr_ifindex);
            return TC_ACT_UNSPEC;
        }
        // bpf_printk("blocking ingress traffic from rediecting to the honey pot interface %d\n", curr_ifindex);
        return TC_ACT_SHOT;
    }

    ip_address_t old_dest_ip = ret.daddr;
    ip_address_t new_dest_ip = next_end_pt->endpoint.ip;
    __u16 old_dest_port = ret.dport;
    __u16 new_dest_port = next_end_pt->endpoint.port;

    bpf_skb_store_bytes(ctx, MAC_DEST_OFF, &next_end_pt->mac_addr, sizeof(next_end_pt->mac_addr), 0);
    if (ret.l4_proto == IPPROTO_TCP)
    {
        set_tcp_ip_dest(ctx, &old_dest_ip, &new_dest_ip);
        set_tcp_port_dest(ctx, old_dest_port, new_dest_port);
    }
    else if (ret.l4_proto == IPPROTO_UDP)
    {
        set_udp_ip_dest(ctx, &old_dest_ip, &new_dest_ip);
        set_udp_port_dest(ctx, old_dest_port, new_dest_port);
    }
    else
    {
        // bpf_printk("ingress traffic with invalid l4 protocol %d", ret.l4_proto);
    }
    
    // bpf_printk("ingress redirecting to %d\n", next_end_pt->interface_index);
    return bpf_redirect(next_end_pt->interface_index, BPF_F_INGRESS);
    
}

SEC("tc")
int tc_egress(struct __sk_buff *ctx) 
{
    __u8 ingress = 0;
	struct from_sk_buff ret;
    if (get_sk_info(ctx, &ret) != 0)
    {
        bpf_printk("unable to get sk info for egress traffic");
        return TC_ACT_UNSPEC;
    }

	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;
	struct ethhdr *l2 = (struct ethhdr *)data;
	if ((void *)(l2 + 1) > data_end)
    {
        bpf_printk("get_sk_info: invalid data pointer");
		return -1;
    }

    struct ip_lpm_key lpm_key = {128, ret.daddr};
    __u8* redirect_ip = (__u8*)bpf_map_lookup_elem(&redirect_ips, &lpm_key);
    if (redirect_ip == NULL)
    {
        struct connection_config_key config_key;
        __builtin_memset(&config_key, 0, sizeof(config_key));
        config_key.local_ip =  ret.saddr;
        config_key.local_port = ret.sport;
        config_key.remote_ip = ret.daddr;
        config_key.remote_port = ret.dport;

        if (send_data_to_rb(ctx, &config_key, &ret, &ingress) == 0)
        {
            // bpf_printk("egress sending data for src port: %d, dest port: %d\n", ret.sport, ret.dport);
        }

        __u8* blocked_ip = (__u8*)bpf_map_lookup_elem(&blocked_ips, &lpm_key);
        if (blocked_ip != NULL)
        {
            bpf_printk("blocking ip for egress traffic\n");
            return TC_ACT_SHOT;
        }

        __u8* blocked_port = (__u8*)bpf_map_lookup_elem(&blocked_ports, &ret.dport);
        if (blocked_port != NULL)
        {
            bpf_printk("blocking port for egress traffic\n");
            return TC_ACT_SHOT;
        }

        __u32 key = 0; // Index 0
        struct net_prot_config *value;
        value = bpf_map_lookup_elem(&config_map, &key);
        if (value == NULL)
        {
            bpf_printk("isolation config not there with tc_egress");
            return TC_ACT_UNSPEC; // no config value is available
        }
        if (value->isolation)
        {
            struct network_tuple current_network_tuple = {ret.daddr, ret.dport, ret.saddr, ret.sport, ret.l4_proto};
            __u8 *value1 = (__u8 *)bpf_map_lookup_elem(&isolation_network_tuple, &current_network_tuple);
            __builtin_memset(&current_network_tuple.local_ip, 0, sizeof(ip_address_t));
            __u8 *value2 = (__u8 *)bpf_map_lookup_elem(&isolation_network_tuple, &current_network_tuple);
            if (value1 == NULL && value2 == NULL) 
            {
                bpf_printk("Permission denied for local port for tc_egress =%d", ret.dport);
                return TC_ACT_SHOT; // Permission denied
            }
        }

        return TC_ACT_UNSPEC;
    }

    __u32 curr_ifindex = ctx->ifindex;
    struct redirection_endpoint_mac end_pt;
    struct redirection_endpoint end_pt_key;
    __builtin_memset(&end_pt, 0, sizeof(end_pt));
    __builtin_memset(&end_pt_key, 0, sizeof(end_pt_key));
    end_pt.interface_index = curr_ifindex;
    for (int i = 0; i < 6; i++)
    {
        end_pt.mac_addr[i] = l2->h_source[i];
    }
    end_pt_key.port = ret.sport;
    end_pt_key.ip = ret.saddr;
    end_pt.endpoint = end_pt_key;
    struct redirection_endpoint_mac* next_end_pt = (struct redirection_endpoint_mac*)bpf_map_lookup_elem(&reverse_redirect_endpoints, &end_pt_key);
    if (next_end_pt == NULL)
    {
        // bpf_printk("blocking egress traffic from rediecting to the honey pot interface %d\n", curr_ifindex);
        return TC_ACT_SHOT;
    }
    ip_address_t old_src_ip = ret.saddr;
    ip_address_t new_src_ip = next_end_pt->endpoint.ip;
    __u16 old_src_port = ret.sport;
    __u16 new_src_port = next_end_pt->endpoint.port;

    bpf_skb_store_bytes(ctx, MAC_SRC_OFF, &next_end_pt->mac_addr, sizeof(next_end_pt->mac_addr), 0);
    if (ret.l4_proto == IPPROTO_TCP)
    {
        set_tcp_ip_src(ctx, &old_src_ip, &new_src_ip);
        set_tcp_port_src(ctx, old_src_port, new_src_port);
    }
    else if (ret.l4_proto == IPPROTO_UDP)
    {
        set_udp_ip_src(ctx, &old_src_ip, &new_src_ip);
        set_udp_port_src(ctx, old_src_port, new_src_port);
    }
    else
    {
        // bpf_printk("egress traffic with invalid l4 protocol %d", ret.l4_proto);
    }
    // bpf_printk("egress honeypotted from %d\n", next_end_pt->interface_index);
    return TC_ACT_OK;
}

