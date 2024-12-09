#include "src/vmlinux.h"
#include "src/conn_structs.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static int SSL_process(struct pt_regs *ctx, int rw) 
{
    int ret = 0;
    u32 zero = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();

    int len = PT_REGS_RC(ctx);
    if (len <= 0)  // no data
    {
        bpf_printk("No data from process %d ssl connection len: %d", pid, len);
        return 0;
    }

    struct probe_SSL_data_t *data = bpf_ringbuf_reserve(&perf_SSL_events, sizeof(struct probe_SSL_data_t), 0);
    if (!data)
    {
        bpf_printk("No ringbuff data from process %d ssl connection", pid);
        return 0;
    }

    data->timestamp_ns = ts;
    data->pid = pid;
    data->tid = ((u32)pid_tgid) & 0xffffffff;
    data->uid = uid;
    data->buf_filled = 0;
    data->rw = rw;

    struct ssl_carry_info* ssl_info = bpf_map_lookup_elem(&SSL_carry_info, &pid_tgid);
    if (ssl_info == 0)
    {
        bpf_ringbuf_discard(data, 0);
        return 0;
    }
    u32 buf_copy_size = min((size_t)MAX_BUF_SIZE, (size_t)len);
    data->len = (u32)len;
    data->req_len = ssl_info->req_len;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));

    if (ssl_info->buff != 0)
        ret = bpf_probe_read_user(&data->buf, buf_copy_size, (char *)(ssl_info->buff));
    bpf_map_delete_elem(&SSL_carry_info, &pid_tgid);

    if (!ret)
        data->buf_filled = 1;
    else
        buf_copy_size = 0;

    bpf_printk("SSL_rw called with len: %d,buffer: %s\n", buf_copy_size, data->buf);
    bpf_ringbuf_submit(data, 0);

    return 0;
}

SEC("uprobe/SSL_rw_custom")
int BPF_UPROBE(handle_ssl_rw_enter, void *ssl, void *buf, int num) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    u32 pid = pid_tgid >> 32;

    struct ssl_carry_info info = {num, (__u64)buf, ts};

    /* store arg info for later lookup */
    bpf_map_update_elem(&SSL_carry_info, &pid_tgid, &info, BPF_ANY);
    bpf_printk("SSL_rw_custom entry called with pid: %d\n", pid);
    return 0;
}

SEC("uretprobe/SSL_read")
int BPF_URETPROBE(handle_ssl_read_exit) 
{
    return SSL_process(ctx, 0);
}

SEC("uretprobe/SSL_write")
int BPF_URETPROBE(handle_ssl_write_exit) 
{
    return SSL_process(ctx, 1);
}

SEC("uprobe/SSL_do_handshake")
int BPF_UPROBE(handle_ssl_do_handshake_entry, void *ssl) 
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 ts = bpf_ktime_get_ns();

    struct ssl_carry_info info = {0, 0, ts};
    /* store arg info for later lookup */
    bpf_map_update_elem(&SSL_carry_info, &pid_tgid, &info, BPF_ANY);
    bpf_printk("SSL_handshake entry called with pid: %d\n", pid);
    return 0;
}

SEC("uretprobe/SSL_do_handshake")
int BPF_URETPROBE(handle_ssl_do_handshake_exit) 
{
    int ret = 0;
    u32 zero = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u32 uid = bpf_get_current_uid_gid();
    u64 ts = bpf_ktime_get_ns();

    ret = PT_REGS_RC(ctx);
    if (ret <= 0)  // handshake failed
        return 0;

    struct ssl_carry_info *tsp = bpf_map_lookup_elem(&SSL_carry_info, &pid_tgid);
    if (tsp == 0)
        return 0;

    struct probe_SSL_data_t *data = bpf_ringbuf_reserve(&perf_SSL_events, sizeof(struct probe_SSL_data_t), 0);
    if (!data)
        return 0;

    data->timestamp_ns = ts;
    data->delta_ns = ts - (tsp->start_ns);
    data->pid = pid;
    data->tid = tid;
    data->uid = uid;
    data->len = 0;
    data->req_len = 0;
    data->buf_filled = 0;
    data->rw = 2;
    bpf_get_current_comm(&data->comm, sizeof(data->comm));
    bpf_map_delete_elem(&SSL_carry_info, &pid_tgid);

    bpf_ringbuf_submit(data, 0);
    bpf_printk("SSL_handshake exit called with pid: %d\n", pid);
    return 0;
}
