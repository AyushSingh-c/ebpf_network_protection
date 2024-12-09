#include "src/vmlinux.h"
#include "src/conn_structs.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("lsm/socket_recvmsg")
int BPF_PROG(bpf_socket_recvmsg, struct socket *sock, struct msghdr *msg, int size, int ret)
{
    if (sock == NULL) 
    {
        bpf_printk("no socket with bpf_socket_recvmsg");
        return 0;
    }

    struct sock *sk = (struct sock *)BPF_CORE_READ(sock, sk);
    if (sk == NULL)
    {
        bpf_printk("no sock with bpf_socket_recvmsg");
        return 0;
    }

    struct sock_common skc;
    int err = BPF_CORE_READ_INTO(&skc, sk, __sk_common);

    if (err != 0)
    {
        bpf_printk("no sock_common with bpf_socket_recvmsg");
        return 0;
    }

    __u16 right_src_port = skc.skc_num;
    __u16 dest_port = ((skc.skc_dport >> 8) & 0xff) + ((skc.skc_dport & 0xff) << 8);

    if ((skc.skc_family != AF_INET && skc.skc_family != AF_INET6) || dest_port == 53 || dest_port == 5353)
    {
        // bpf_printk("no network data with bpf_socket_recvmsg");
        return 0;
    }

    // if (ret != 0)
    // {
    //     bpf_printk("already ret not zero but %d with bpf_socket_recvmsg", ret);
    // }

    __u32 key = 0; // Index 0
    struct net_prot_config *value;
    value = bpf_map_lookup_elem(&config_map, &key);
    if (value == NULL)
    {
        bpf_printk("isolation config not there with bpf_socket_recvmsg");
        return 0; // no config value is available
    }
    
    if (value->isolation)
    {
        bpf_printk("started isolation with bpf_socket_recvmsg\n");
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        pid_t pid = bpf_get_current_pid_tgid() >> 32;
        __u8 *value = (__u8 *)bpf_map_lookup_elem(&isolation_pids, &pid);
        
        if (value == NULL) 
        {
            bpf_printk("Permission denied for pid for bpf_socket_recvmsg =%d", pid);
            return -EACCES; // Permission denied
            // return 0;
        }
        bpf_printk("Permission not denied for pid for bpf_socket_recvmsg pid: %d", pid);
    }

    
    return 0; // Allow receiving messages
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(bpf_socket_sendmsg, struct socket *sock, struct msghdr *msg, size_t len, int ret) 
{
    if (sock == NULL) 
    {
        bpf_printk("no socket with bpf_socket_sendmsg");
        return 0;
    }

    struct sock *sk = (struct sock *)BPF_CORE_READ(sock, sk);
    if (sk == NULL)
    {
        bpf_printk("no sock with bpf_socket_sendmsg");
        return 0;
    }

    struct sock_common skc;
    int err = BPF_CORE_READ_INTO(&skc, sk, __sk_common);
    __u16 right_src_port = skc.skc_num;
    __u16 dest_port = ((skc.skc_dport >> 8) & 0xff) + ((skc.skc_dport & 0xff) << 8);

    if (err != 0)
    {
        bpf_printk("no sock_common with bpf_socket_sendmsg");
        return 0;
    }

    if ((skc.skc_family != AF_INET && skc.skc_family != AF_INET6) || right_src_port == 53 || right_src_port == 5353)
    {
        // bpf_printk("no network data with bpf_socket_sendmsg");
        return 0;
    }
    // if (ret != 0)
    // {
    //     bpf_printk("already ret not zero but %d with bpf_socket_sendmsg", ret);
    // }

    __u32 key = 0; // Index 0
    struct net_prot_config *value;
    value = bpf_map_lookup_elem(&config_map, &key);
    if (value == NULL)
    {
        bpf_printk("isolation config not there with bpf_socket_sendmsg");
        return 0; // no config value is available
    }
    
    if (value->isolation)
    {
        bpf_printk("started isolation with bpf_socket_sendmsg\n");
        struct task_struct *task;
        task = (struct task_struct *)bpf_get_current_task();
        pid_t pid = bpf_get_current_pid_tgid() >> 32;
        __u8 *value = (__u8 *)bpf_map_lookup_elem(&isolation_pids, &pid);
        
        if (value == NULL) 
        {
            bpf_printk("Permission denied for pid for bpf_socket_sendmsg =%d\n", pid);
            return -EACCES; // Permission denied
            // return 0;
        }
        bpf_printk("Permission not denied for pid for bpf_socket_sendmsg=%d\n", pid);
    }

    
    return 0; // Allow receiving messages
}

