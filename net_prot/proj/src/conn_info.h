#ifndef COMMON_LIB_H
#define COMMON_LIB_H

typedef unsigned char __u8;
typedef short unsigned int __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define MAX_BUF_SIZE 4096
#define MAX_PROCESS_PATH_LEN 4096
#define MAX_PROC_COUNT 4194304
#define IPV4_ADDR_LEN 4
#define IPV6_ADDR_LEN 8
#define KPATH_ENTRIES       (16)
#define KPATH_ENTRY_SIZE    (256)
#define MAX_CMDLINE_ARGS    (16)
#define SEPARATOR_SIZE      (1)

#define MAX_SSL_BUF_SIZE 8192
#define TASK_COMM_LEN 256

// from /sys/kernel/debug/tracing/events/net/netif_receive_skb/format
struct trace_event_raw_netif_receive_skb {
	unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count; 
    int common_pid; 

    void * skbaddr;
	unsigned int len;
	__u32 __data_loc_name;
	char __data[0];
};

struct ssl_carry_info
{
    __u32 req_len;
    __u64 buff;
    __u64 start_ns;
};

struct probe_SSL_data_t {
    __u64 timestamp_ns;  // Timestamp (nanoseconds)
    __u64 delta_ns;      // Time taken to process the data
    __u32 pid;           // Process ID
    __u32 tid;           // Thread ID
    __u32 uid;           // User ID
    __u32 len;           // Length of actual read/write data
    __u32 req_len;       // Requested length of read/write data
    int buf_filled;      // Whether buffer is filled completely
    int rw;              // Read or Write or Handshake (0 for read, 1 for write, 2 for handshake)
    char comm[TASK_COMM_LEN]; // Process name
    __u8 buf[MAX_SSL_BUF_SIZE];  // Data buffer
};

typedef struct 
{
    pid_t pid;
    pid_t parent_pid;
    union
    {
        char full_path[MAX_PROCESS_PATH_LEN];
        char dentries[KPATH_ENTRIES][KPATH_ENTRY_SIZE];
    };
    unsigned long dentry_sizes[KPATH_ENTRIES];
    unsigned int dentries_number;
} process_info;

enum event_kpath_type
{
    kpath_type_process_path = 0,
    kpath_type_process_cwd = 1
};

typedef enum {
    IPV4,
    IPV6
} ip_version_t;

typedef struct {
    union {
        __u8 ipv4[IPV4_ADDR_LEN];
        __u16 ipv6[IPV6_ADDR_LEN];
    } addr;
    ip_version_t version;
} ip_address_t;

struct ip_lpm_key
{
    __u32 prefix_len;
    ip_address_t addr;
};

// to keep pkt data in an array map
struct pkt_key
{
    __u64 timestamp;
    ip_address_t src_ip;
    __u16 src_port;
    ip_address_t dest_ip;
    __u16 dest_port;
};

// define a particular connection with dir
struct directional_connection_key
{
    ip_address_t src_ip;
    __u16 src_port;
    ip_address_t dest_ip;
    __u16 dest_port;
};

struct connection_config_key
{
    ip_address_t local_ip;
    __u16 local_port;
    ip_address_t remote_ip;
    __u16 remote_port;
};

struct network_tuple
{
    ip_address_t local_ip;
    __u16 local_port;
    ip_address_t remote_ip;
    __u16 remote_port;
    __u8 l4_proto;
};

struct redirection_endpoint
{
    ip_address_t ip;
    __u16 port;
};

struct redirection_endpoint_mac
{
    __u32 interface_index;
    unsigned char mac_addr[6];
    struct redirection_endpoint endpoint;
};

struct connection_info
{
    __u32 interface_index;
};

struct connection_config_value
{
    __u8 stop_ingress_pkt_data;  //only 0(get it), 1(dont get it)
    __u8 stop_egress_pkt_data;  //only 0(get it), 1(dont get it)
    // can add connection specific configs like should drop pkt or not
};

struct net_prot_config
{
    __u8 isolation;  //only 0(no isolation), 1(start isolation)
    int16_t redirection_if_index;
};

struct protocols
{
    __u8 l2_protocol;
    __u8 l3_protocol;   //ipv4 ipv6 arp
    __u8 l4_protocol;   //tcp udp icmp
    __u8 l5_protocol;   //ssl tls
    __u8 l6_protocol;   //sip sdp rtp rtcp
    __u8 l7_protocol;   // http ssh ftp dns
};

struct pkt_info
{
    __u64 timestamp;
    struct directional_connection_key conn_key;
    struct protocols proto;
    __u32 ifindex;
    __u64 proc;
    unsigned int pk_len;
    __u8 ingress; // only 0(egress), 1(ingress)
};

struct connection_kern_data
{
    __u64 timestamp;
    struct connection_config_key conn_key;
    unsigned int pk_len;
    __u8 ingress;  // only 0(egress), 1(ingress)
    struct protocols proto;
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
    unsigned int pk_len;
    ip_address_t saddr;
    __u16 sport;
    ip_address_t daddr;
    __u16 dport;
    __u8 l3_proto;
    __u8 l4_proto;
};
#endif