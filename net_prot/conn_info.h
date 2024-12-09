typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define MAX_BUF_SIZE 2024

// to keep pkt data in an array map
struct pkt_key
{
    __u64 timestamp;
    __u32 src_ip;
    __u16 src_port;
    __u32 dest_ip;
    __u16 dest_port;
};

// define a particular connection with dir
struct directional_connection_key
{
    __u32 src_ip;
    __u16 src_port;
    __u32 dest_ip;
    __u16 dest_port;
};

struct connection_config_key
{
    __u32 local_ip;
    __u16 local_port;
    __u32 remote_ip;
    __u16 remote_port;
};

struct connection_config_value
{
    __u8 stop_ingress_pkt_data;  //only 0(get it), 1(dont get it)
    __u8 stop_egress_pkt_data;  //only 0(get it), 1(dont get it)
    // can add connection specific configs like should drop pkt or not
};

struct protocols
{
    __u8 l3_protocol;   //ipv4 ipv6 arp
    __u8 l4_protocol;   //tcp udp icmp
    __u8 l5_protocol;   //ssl tls
    __u8 l7_protocol;   // http ssh ftp dns
};

struct pkt_info
{
    __u64 timestamp;
    struct directional_connection_key conn_key;
    struct protocols proto;
    __u32 ifindex;
    __u64 proc;
    __u64 pk_len;
    __u8 ingress; // only 0(egress), 1(ingress)
};

struct connection_kern_data
{
    struct connection_config_key conn_key;
    __u64 pk_len;
    __u8 ingress;  // only 0(egress), 1(ingress)
    __u8 buf[MAX_BUF_SIZE];
};

struct connection_setup_info 
{
    __u64 timestamp;
    __u64 proc;
    __u32 ifindex;
    struct directional_connection_key conn_key;
    struct protocols proto;
    // is_incoming=[conn_flow&1] is_starting_pkt=[(conn_flow>>1)&1]
    __u8 conn_flow; // start_or_end + incoming_or_outgoing
};

struct from_sk_buff
{
    __u8 valid;
    __u32 ifindex;
    __u64 pk_len;
    __u32 saddr;
    __u16 sport;
    __u32 daddr;
    __u16 dport;
    __u8 l3_proto;
    __u8 l4_proto;
};