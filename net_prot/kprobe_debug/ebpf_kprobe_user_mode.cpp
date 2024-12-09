#include <errno.h>
#include <iostream>
#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <thread>
#include <atomic>
#include <chrono>

#include "ebpf_structs.h"

// ok build thing properly
enum bpf_link_type {
	BPF_LINK_TYPE_UNSPEC = 0,
	BPF_LINK_TYPE_RAW_TRACEPOINT = 1,
	BPF_LINK_TYPE_TRACING = 2,
	BPF_LINK_TYPE_CGROUP = 3,
	BPF_LINK_TYPE_ITER = 4,
	BPF_LINK_TYPE_NETNS = 5,
	BPF_LINK_TYPE_XDP = 6,
	BPF_LINK_TYPE_PERF_EVENT = 7,
	BPF_LINK_TYPE_KPROBE_MULTI = 8,
	BPF_LINK_TYPE_STRUCT_OPS = 9,
	BPF_LINK_TYPE_NETFILTER = 10,
	BPF_LINK_TYPE_TCX = 11,
	BPF_LINK_TYPE_UPROBE_MULTI = 12,
	BPF_LINK_TYPE_NETKIT = 13,
	BPF_LINK_TYPE_SOCKMAP = 14,
	__MAX_BPF_LINK_TYPE,
};

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

std::string parse_ip(__u32 ip, __u16 port)
{
	return std::to_string(ip & 0xff) + "." + std::to_string((ip >> 8) & 0xff) + "." + std::to_string((ip >> 16) & 0xff) + "." + std::to_string((ip >> 24) & 0xff) + ":" + std::to_string(port);
}

std::string parse_ip_protocol(__u8 proto)
{
	switch(proto)
	{
		case 0:
			return "IPPROTO_IP";
		case 1:
			return "IPPROTO_ICMP";
		case 2:
			return "IPPROTO_IGMP";
		case 4:
			return "IPPROTO_IPIP";
		case 6:
			return "IPPROTO_TCP";
		case 8:
			return "IPPROTO_EGP";
		case 12:
			return "IPPROTO_PUP";
		case 17:
			return "IPPROTO_UDP";
		case 22:
			return "IPPROTO_IDP";
		case 29:
			return "IPPROTO_TP";
		case 33:
			return "IPPROTO_DCCP";
		case 41:
			return "IPPROTO_IPV6";
		case 46:
			return "IPPROTO_RSVP";
		case 47:
			return "IPPROTO_GRE";
		case 50:
			return "IPPROTO_ESP";
		case 51:
			return "IPPROTO_AH";
		case 92:
			return "IPPROTO_MTP";
		case 94:
			return "IPPROTO_BEETPH";
		case 98:
			return "IPPROTO_ENCAP";
		case 103:
			return "IPPROTO_PIM";
		case 108:
			return "IPPROTO_COMP";
		case 132:
			return "IPPROTO_SCTP";
		case 136:
			return "IPPROTO_UDPLITE";
		case 137:
			return "IPPROTO_MPLS";
		case 255:
			return "IPPROTO_RAW";
		default:
			return "UNKOWN_PROTO";
	}
}

int handle_event(void *ctx, void *data, size_t size)
{
    struct connection_creation_info *info = (connection_creation_info *)data;
    printf("%s packet src_ip: %s, dest_ip: %s, device name: %s, protocol: %s\n",
		   info->ingress ? "Ingress" : "Egress",
           parse_ip(info->src_ip, info->src_port).c_str(), 
		   parse_ip(info->dest_ip, info->dest_port).c_str(), 
		   info->dev_name, 
		   parse_ip_protocol(info->protocol).c_str());
	return 0;
}

std::atomic<bool> running(true);

void checkInput() {
    std::string userInput;
    while (running) {
		std::cin.get();
        running = false;
    }
}

int main()
{
	char filename[] = "/home/ayush/testing/net_prot/kprobe/ebpf_kprobe.bpf.o";
	struct bpf_object *obj;
    int err;

	std::cout << "starting with ebpf code open and load" << std::endl;

    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

	std::cout << "loaded the prog file successfully" << std::endl;

    struct bpf_program *ingress_prog;
    ingress_prog = bpf_object__find_program_by_name(obj, "sk_buff_from_ingress");
    if (!ingress_prog) {
        fprintf(stderr, "ERROR: finding program sk_buff_from_ingress failed\n");
        return 1;
    }

    if (!bpf_program__attach_kprobe(ingress_prog, false, "__netif_receive_skb")) {
        fprintf(stderr, "ERROR: attaching kprobe to __netif_receive_skb failed\n");
        return 1;
    }

    struct bpf_program *egress_prog;
    egress_prog = bpf_object__find_program_by_name(obj, "sk_buff_from_egress");
    if (!egress_prog) {
        fprintf(stderr, "ERROR: finding program sk_buff_from_egress failed\n");
        return 1;
    }

    if (!bpf_program__attach_kprobe(egress_prog, false, "__dev_queue_xmit")) {
        fprintf(stderr, "ERROR: attaching kprobe to __dev_queue_xmit failed\n");
        return 1;
    }

	struct bpf_program *prog_temp;
    bpf_object__for_each_program(prog_temp, obj) {
        const char *prog_name = bpf_program__name(prog_temp);
        printf("Program name: %s\n", prog_name);
    }

	// Find the BPF program by section name
    struct bpf_program *fentry_egress_prog = bpf_object__find_program_by_name(obj, "fentry_dev_queue_xmit");
    if (!fentry_egress_prog) {
        fprintf(stderr, "Failed to find BPF program by title fentry/__dev_queue_xmit\n");
        return 1;
    }

	int fentry_egress_prog_fd;
    // Get the file descriptor of the BPF program
    fentry_egress_prog_fd = bpf_program__fd(fentry_egress_prog);
    if (fentry_egress_prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program file descriptor\n");
        return 1;
    }

    // Attach the BPF program to the function
    struct bpf_link *fentry_egress_link = bpf_program__attach(fentry_egress_prog);
    if (libbpf_get_error(fentry_egress_link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

	// Find the BPF program by section name
    struct bpf_program *fentry_ingress_prog = bpf_object__find_program_by_name(obj, "fexit_netif_receive_skb");
    if (!fentry_ingress_prog) {
        fprintf(stderr, "Failed to find BPF program by title fentry/__netif_receive_skb\n");
        return 1;
    }

	int fentry_ingress_prog_fd;
    // Get the file descriptor of the BPF program
    fentry_ingress_prog_fd = bpf_program__fd(fentry_ingress_prog);
    if (fentry_ingress_prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program file descriptor\n");
        return 1;
    }

    // Attach the BPF program to the function
    struct bpf_link *fentry_ingress_link = bpf_program__attach(fentry_ingress_prog);
    if (libbpf_get_error(fentry_ingress_link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return 1;
    }

    printf("BPF programs loaded and attached successfully\n");

	struct ring_buffer *rb = NULL;
    int map_fd = bpf_obj_get("/sys/fs/bpf/connection_creation_info_ring_buff");
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        perror("ring_buffer__new");
        return 1;
    }

	std::cout << "starting the polling for info" <<std::endl;
	std::thread inputThread(checkInput);

    while (running) 
	{
        int err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err < 0) 
		{
            perror("ring_buffer__poll");
            break;
        }
    }

	inputThread.join();

    ring_buffer__free(rb);
	bpf_object__close(obj);

	return 0;
}


