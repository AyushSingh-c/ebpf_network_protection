#include <errno.h>
#include <iostream>
#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <net/if.h>
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


#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <xdp/libxdp.h>

int unload_xdp(int interface_seq, char* interface_name)
{
	struct xdp_multiprog *mp = NULL;
	int err = EXIT_FAILURE;
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);

	mp = xdp_multiprog__get_from_ifindex(interface_seq);
	if (libxdp_get_error(mp)) {
		fprintf(stderr, "Unable to get xdp_dispatcher program: %s\n",
			strerror(errno));
		goto out;
	} else if (!mp) {
		fprintf(stderr, "No XDP program loaded on %s\n", interface_name);
		mp = NULL;
		goto out;
	}

	err = xdp_multiprog__detach(mp);
	if (err) 
	{
		fprintf(stderr, "Unable to detach XDP program: %s\n",
			strerror(-err));
		goto out;
	}
out:
	xdp_multiprog__close(mp);
	return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

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
    printf("src_ip: %s, dest_ip: %s, protocol: %s\n",
           parse_ip(info->src_ip, info->src_port).c_str(), parse_ip(info->dest_ip, info->dest_port).c_str(), parse_ip_protocol(info->protocol).c_str());
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

int main(int argc, char* argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv << " <integer>" << std::endl;
        return 1;
    }

    int interface_seq = std::atoi(argv[1]);     //ip link show will give the interface number
    std::cout << "using interface index for: " << interface_seq <<std::endl; 

    char interface_name[256];
    if (if_indextoname(interface_seq, interface_name) == nullptr) {
        std::cerr << "Error: " << std::strerror(errno) << std::endl;
        return 1;
    }
    std::cout << "using interface name for: " << interface_name <<std::endl; 

	char filename[] = "/home/ayush/testing/net_prot/xdp_ingress_debug/ebpf_xdp_ingress.bpf.o";
	char progname[] = "xdp_parser";
	struct xdp_program *prog;
	char errmsg[1024];
	int prog_fd, err; // = EXIT_SUCCESS;

    prog = xdp_program__open_file(filename, progname, NULL);
    if (!prog) {
        fprintf(stderr, "Failed to open XDP program\n");
        return 1;
    }

	std::cout << "opened the prog file successfully" << std::endl;

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, bpf_opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts,
                            .opts = &bpf_opts,
                            .prog_name = progname,
                            .open_filename = filename);

    prog = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(prog);
	if (err) 
    {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Couldn't get XDP program %s: %s\n",
			progname, errmsg);
		return err;
	}

    err = xdp_program__attach(prog, interface_seq, XDP_MODE_UNSPEC, 0);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "Couldn't attach XDP program on iface '%s' : %s (%d)\n",
			interface_name, errmsg, err);
		return err;
	}

	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	prog_fd = xdp_program__fd(prog);
	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: can't get prog info - %s\n",
			strerror(errno));
		return err;
	}

	printf("Success: Loading "
	       "XDP prog name:%s(id:%d) on device:%s(ifindex:%d)\n",
	       info.name, info.id, interface_name, interface_seq);

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

    // Clean up
    ring_buffer__free(rb);
	unload_xdp(interface_seq, interface_name);

	return 0;
}


