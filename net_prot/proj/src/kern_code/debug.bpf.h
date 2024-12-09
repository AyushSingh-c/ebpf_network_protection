#ifndef DEBUG_UTILS_H
#define DEBUG_UTILS_H

#include "src/vmlinux.h"
#include "src/conn_structs.bpf.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

static void print_redirection_endpoint(struct redirection_endpoint_mac* end_pt)
{
    bpf_printk("interface index: %d", end_pt->interface_index);
    bpf_printk("mac address %x:%x:%x", end_pt->mac_addr[0], end_pt->mac_addr[1], end_pt->mac_addr[2]);
    bpf_printk("%x:%x:%x", end_pt->mac_addr[3], end_pt->mac_addr[4], end_pt->mac_addr[5]);
    if (end_pt->endpoint.ip.version == IPV6)
    {
        bpf_printk("ipv6 address: %x:%x:%x", end_pt->endpoint.ip.addr.ipv6[0], end_pt->endpoint.ip.addr.ipv6[1], end_pt->endpoint.ip.addr.ipv6[2]);
        bpf_printk("%x:%x:%x", end_pt->endpoint.ip.addr.ipv6[3], end_pt->endpoint.ip.addr.ipv6[4], end_pt->endpoint.ip.addr.ipv6[5]);
    }
    else
    {
        bpf_printk("ipv4 address: %x:%x:%x", end_pt->endpoint.ip.addr.ipv4[0], end_pt->endpoint.ip.addr.ipv4[1], end_pt->endpoint.ip.addr.ipv4[2]);
        bpf_printk("%x", end_pt->endpoint.ip.addr.ipv4[3]);
    }
    bpf_printk("port: %d", end_pt->endpoint.port);
}

#endif