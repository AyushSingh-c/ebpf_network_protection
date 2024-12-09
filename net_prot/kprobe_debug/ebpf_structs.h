typedef unsigned int __u32;
typedef short unsigned int __u16;
typedef unsigned char __u8;

struct connection_creation_info {
    __u32 src_ip;
    __u32 dest_ip;
    __u16 src_port;
    __u16 dest_port;
    __u8 protocol;
    char dev_name[16];
    bool ingress;
};