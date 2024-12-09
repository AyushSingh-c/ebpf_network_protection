#include <errno.h>
#include <iostream>
#include <cstdlib>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <net/if.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <dirent.h>
#include <cctype>
#include <algorithm>
#include <fcntl.h>
#include <sys/stat.h>
#include <map>
#include <set>
#include <functional>
#include <variant>
#include <filesystem>
#include <cstdio>
#include <format>
#include <regex>

#include "conn_info.h"
#include "parser.h"

// ok build things properly pls
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
#include <xdp/libxdp.h>

struct packet_data
{
    __u64 timestamp;
    __u64 proc;
    bool ingress;
    __u64 pk_len;
};

struct connection_data
{
	__u64 timestamp;
	Parser conn_parser;
	size_t checksum;
	__u32 local_ip;
    __u16 local_port;
    __u32 remote_ip;
    __u16 remote_port;
    struct protocols proto{127, 127, 127, 127};
	bool incoming;
    std::string dev_name;
	std::vector<struct packet_data> pkts;
	__u64 ingress_data_len;
	__u64 egress_data_len;
	std::vector<std::vector<__u8>> ingress_pkt_inspection_data; 
	std::vector<std::vector<__u8>> egress_pkt_inspection_data; 
};

class connection_flow_map
{
public:
	connection_flow_map(size_t maxSize) : maxSize(maxSize) {}

	void insert_connection_data(size_t key, std::vector<__u8> data, bool ingress)
	{
		if (ingress)
		{
			if (flow_map[key].ingress_data_len < MAX_BUF_SIZE)
			{
				flow_map[key].ingress_pkt_inspection_data.emplace_back(data);
				flow_map[key].ingress_data_len += data.size();
			}
			if (flow_map[key].proto.l7_protocol == 127)
			{
				struct pkt_parse_state state {data, true};
				flow_map[key].proto.l7_protocol = static_cast<int>(flow_map[key].conn_parser.parse(state));
			}
		}
		else
		{
			if (flow_map[key].egress_data_len < MAX_BUF_SIZE)
			{
				flow_map[key].egress_pkt_inspection_data.emplace_back(data);
				flow_map[key].egress_data_len += data.size();
			}
			if (flow_map[key].proto.l7_protocol == 127)
			{
				struct pkt_parse_state state {data, false};
				flow_map[key].proto.l7_protocol = static_cast<int>(flow_map[key].conn_parser.parse(state));
			}
		}
	}

	void insert_conn(struct connection_data& data)
	{
		auto it = flow_map.find(data.checksum);
        if (it != flow_map.end()) 
		{
			if (data.pkts.size() == 0)
				flow_map[data.checksum].incoming = data.incoming;
			
			if (flow_map[data.checksum].proto.l3_protocol == 127)
				flow_map[data.checksum].proto.l3_protocol = data.proto.l3_protocol;
			if (flow_map[data.checksum].proto.l4_protocol == 127)
				flow_map[data.checksum].proto.l4_protocol = data.proto.l4_protocol;

			for (auto pkt : data.pkts)
				flow_map[data.checksum].pkts.push_back(pkt);
        } 
		else 
		{
            if (flow_map.size() >= maxSize) 
			{
				if (channel_less_proto.size() == 0)
				{
					auto data_info = channel_proto.begin();
					flow_map.erase(data_info->second);
					channel_proto.erase(data_info);
				}
				else
				{
					auto data_info = channel_less_proto.begin();
					flow_map.erase(data_info->second);
					channel_less_proto.erase(data_info);
				}
            }
			flow_map.insert({data.checksum, data});
			if (is_channel_proto(data.proto.l4_protocol))
			{
				channel_proto.insert({data.timestamp, data.checksum});
			}
			else
			{
				channel_less_proto.insert({data.timestamp, data.checksum});
			}
        }
	}

	void remove_conn(size_t key)
	{
		struct connection_data data = flow_map[key];
		channel_proto.erase({data.timestamp, data.checksum});
		channel_less_proto.erase({data.timestamp, data.checksum});
		flow_map.erase(data.checksum);
	}

	struct connection_data find(size_t key)
	{
		std::unique_lock<std::mutex> lock(mtx);
		auto id = flow_map.find(key);
		if (id != flow_map.end())
			return id->second;
		return connection_data{};
	}

	size_t get_hash_key(__u32 local_ip, __u16 local_port, __u32 remote_ip, __u16 remote_port)
	{
		__u64 local = (local_ip << 17) + local_port;
		__u64 remote = (remote_ip << 17) + remote_port;
		std::string temp = ((local > remote) ? std::to_string(local) + std::to_string(remote) : std::to_string(remote) + std::to_string(local));
    	return hasher(temp);
	}

	bool should_stop_ingress_pkt_inspection(size_t key)
	{
		return flow_map[key].ingress_data_len >= MAX_BUF_SIZE;
	}

	bool should_stop_egress_pkt_inspection(size_t key)
	{
		return flow_map[key].egress_data_len >= MAX_BUF_SIZE;
	}

	size_t get_map_size()
	{
		return flow_map.size();
	}

private:
    size_t maxSize;
	std::hash<std::string> hasher;
    std::map<size_t, struct connection_data> flow_map;
    std::set<std::pair<__u64, size_t>> channel_proto;
    std::set<std::pair<__u64, size_t>> channel_less_proto;
	std::mutex mtx;

	bool is_channel_proto(__u8 l4_protocol)
	{
		return l4_protocol == 6; // IPPROTO_TCP
	}
};

struct map_fd_ctx
{
	int config_map_fd;
	int pkt_data_map_fd;
};

static class connection_flow_map connection_data_map(200000);
static std::atomic<bool> running(true);
static struct bpf_object *obj;
static std::string output_file_path;

__u32 get_correct_port(__u32 port)
{
	return ((port >> 8) & 0xff) + ((port & 0xff) << 8);
}

std::string parse_ip(__u32 ip, __u32 port)
{
	return std::to_string(ip & 0xff) + "." + std::to_string((ip >> 8) & 0xff) + "." + std::to_string((ip >> 16) & 0xff) + "." + std::to_string((ip >> 24) & 0xff) + ":" + std::to_string(get_correct_port(port));
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

void list_prog()
{
    struct bpf_program *prog_temp;
    bpf_object__for_each_program(prog_temp, obj) 
    {
        const char *prog_name = bpf_program__name(prog_temp);
        printf("Program name: %s\n", prog_name);
    }
}

void load_ebpf_obj(std::string filename)
{
    int err;

	// std::cout << "starting with ebpf code open and load" << std::endl;

    obj = bpf_object__open_file(filename.c_str(), NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return;
    }

	// std::cout << "loaded the prog file successfully" << std::endl;

    list_prog();
}

int load_fentry_module(std::string module_name)
{
    struct bpf_program *fentry_egress_prog = bpf_object__find_program_by_name(obj, module_name.c_str());
    if (!fentry_egress_prog) {
        fprintf(stderr, "Failed to find BPF program by title fentry/__dev_queue_xmit\n");
        return -1;
    }

	int fentry_egress_prog_fd;
    fentry_egress_prog_fd = bpf_program__fd(fentry_egress_prog);
    if (fentry_egress_prog_fd < 0) {
        fprintf(stderr, "Failed to get BPF program file descriptor\n");
        return -1;
    }

    struct bpf_link *fentry_egress_link = bpf_program__attach(fentry_egress_prog);
    if (libbpf_get_error(fentry_egress_link)) {
        fprintf(stderr, "Failed to attach BPF program\n");
        return -1;
    }

    // printf("Fentry BPF programs loaded and attached successfully\n");
    return 0;
}

std::string int_to_hex(int value) 
	{
		std::ostringstream oss;
		oss << std::hex << value;
		std::string ret = oss.str();
		if (value < 16)
			ret = "0" + ret;
		return ret;
	}

int handle_event_pkt(void *ctx, void *data, size_t size)
{
    struct pkt_info *info = (pkt_info *)data;
	char interface_name[256];
    if_indextoname(info->ifindex, interface_name);

	__u32 local_ip = (info->ingress&1) ? info->conn_key.dest_ip : info->conn_key.src_ip;
	__u16 local_port = (info->ingress&1) ? info->conn_key.dest_port : info->conn_key.src_port;
	__u32 remote_ip = (info->ingress&1) ? info->conn_key.src_ip : info->conn_key.dest_ip;
	__u16 remote_port = (info->ingress&1) ? info->conn_key.src_port : info->conn_key.dest_port;

	struct connection_data temp = connection_data {
		info->timestamp,
		Parser{},
		connection_data_map.get_hash_key(
			local_ip, 
			local_port, 
			remote_ip, 
			remote_port),
		local_ip, 
		local_port, 
		remote_ip, 
		remote_port, 
		{info->proto.l3_protocol , info->proto.l4_protocol, 127, 127},
		0, // dummy
		interface_name,
		std::vector<struct packet_data>
		{
			packet_data
			{
				info->timestamp,
				info->proc,
				(info->ingress != 0),
				info->pk_len
			}
		},
		{},
		{}
	};

	connection_data_map.insert_conn(temp);


	std::stringstream pkt_summ;
	pkt_summ << ((info->ingress == 0) ? "Egress" : "Ingress") << " packet src_ip: " << parse_ip(info->conn_key.src_ip, info->conn_key.src_port).c_str()
		<< ", dest_ip: " << parse_ip(info->conn_key.dest_ip, info->conn_key.dest_port).c_str() << ", device name: " << interface_name << ", ip protocol: "
		<< parse_ip_protocol(info->proto.l4_protocol).c_str() << ", pkt length: " << info->pk_len << ", proc pid: " << std::to_string(info->proc).c_str()
		<< ", len: " << connection_data_map.find(temp.checksum).pkts.size() << ", key: " << temp.checksum << "\n";

	FILE* file_output = fopen(output_file_path.c_str(), "a");
    if (!file_output) 
	{
        std::cerr << "Error opening file: " << output_file_path << std::endl;
        return 1;
    }

    fprintf(file_output, "PKT INFO: %s", pkt_summ.str().c_str());
	
	fclose(file_output);

	// printf("%s packet src_ip: %s, dest_ip: %s, device name: %s, ifindex: %d, ip protocol: %s, pkt length: %lld, proc info: %s, len: %lu, key: %lu\n",
	// 	   (info->ingress == 0) ? "Egress" : "Ingress",
    //        parse_ip(info->conn_key.src_ip, info->conn_key.src_port).c_str(), 
	// 	   parse_ip(info->conn_key.dest_ip, info->conn_key.dest_port).c_str(), 
	// 	   interface_name, 
	// 	   info->ifindex,
	// 	   parse_ip_protocol(info->proto.l4_protocol).c_str(),
    //        info->pk_len,
	// 	   std::to_string(info->proc).c_str(),
	// 	   connection_data_map.find(temp.checksum).pkts.size(),
	// 	   temp.checksum);
	return 0;
}

int handle_event_conn(void *ctx, void *data, size_t size)
{
    struct connection_setup_info *info = (connection_setup_info *)data;
	char interface_name[256];
    if_indextoname(info->ifindex, interface_name);

	__u32 local_ip = (info->conn_flow&1) ? info->conn_key.dest_ip : info->conn_key.src_ip;
	__u16 local_port = (info->conn_flow&1) ? info->conn_key.dest_port : info->conn_key.src_port;
	__u32 remote_ip = (info->conn_flow&1) ? info->conn_key.src_ip : info->conn_key.dest_ip;
	__u16 remote_port = (info->conn_flow&1) ? info->conn_key.src_port : info->conn_key.dest_port;

	struct connection_data temp = connection_data {
		info->timestamp,
		Parser{},
		connection_data_map.get_hash_key(
			local_ip, 
			local_port, 
			remote_ip, 
			remote_port),
		local_ip, 
		local_port, 
		remote_ip, 
		remote_port,
		{info->proto.l3_protocol , info->proto.l4_protocol, 127, 127},
		(info->conn_flow == 3),
		interface_name,
		std::vector<struct packet_data>{},
		{},
		{}
	};

	struct connection_config_key key { 
		temp.local_ip,
		temp.local_port,
		temp.remote_ip,
		temp.remote_port
	};

	struct connection_config_value value_start {
		0,
		0
	};

	int config_map_fd = bpf_object__find_map_fd_by_name(obj, "connection_config");
    if (config_map_fd < 0) {
        fprintf(stderr, "Error finding map\n");
		bpf_object__close(obj);
        return 1;
    }

	if ((info->conn_flow>>1)&1) //start conn
	{
		connection_data_map.insert_conn(temp);
		bpf_map_update_elem(config_map_fd, &key, &value_start, BPF_ANY);
	}
	else //end conn
	{
		connection_data_map.remove_conn(temp.checksum);
		bpf_map_delete_elem(config_map_fd, &key);
	}

	std::stringstream conn_summ;
	conn_summ << ((info->conn_flow&1) ? "Incoming " : "Outgoing ") << (((info->conn_flow>>1)&1) ? "starting" : "ending") << " connection src_ip: "
		<< parse_ip(info->conn_key.src_ip, info->conn_key.src_port).c_str() << ", dest_ip: " << parse_ip(info->conn_key.dest_ip, info->conn_key.dest_port).c_str() 
		<< ", device name: " << info->ifindex << ", ip protocol: " << parse_ip_protocol(info->proto.l4_protocol).c_str() << ", proc pid: " << std::to_string(info->proc).c_str()
		<< ", len: " << connection_data_map.find(temp.checksum).pkts.size() << ", key: " << temp.checksum << "connections maintained: " << connection_data_map.get_map_size() << "\n";

	FILE* file_output = fopen(output_file_path.c_str(), "a");
    if (!file_output) 
	{
        std::cerr << "Error opening file: " << output_file_path << std::endl;
        return 1;
    }

	fprintf(file_output, "CONN INFO: %s", conn_summ.str().c_str());
	fclose(file_output);

	// printf("%s connection src_ip: %s, dest_ip: %s, device name: %s, ifindex: %d, ip protocol: %s, proc info: %s, len: %lu, key: %lu\n",
	// 	   (info->conn_flow&1) ? "Incoming" : "Outgoing",
    //        parse_ip(info->conn_key.src_ip, info->conn_key.src_port).c_str(), 
	// 	   parse_ip(info->conn_key.dest_ip, info->conn_key.dest_port).c_str(), 
	// 	   interface_name, 
	// 	   info->ifindex,
	// 	   parse_ip_protocol(info->proto.l4_protocol).c_str(),
	// 	   std::to_string(info->proc).c_str(),
	// 	   connection_data_map.find(temp.checksum).pkts.size(),
	// 	   temp.checksum);
	return 0;

}

int handle_event_conn_data(void *ctx, void *data, size_t size)
{
    struct connection_kern_data *info = (connection_kern_data *)data;

	struct connection_config_key key { 
		info->conn_key.local_ip,
		info->conn_key.local_port,
		info->conn_key.remote_ip,
		info->conn_key.remote_port
	};

	size_t checksum = connection_data_map.get_hash_key(
		info->conn_key.local_ip, 
		info->conn_key.local_port, 
		info->conn_key.remote_ip, 
		info->conn_key.remote_port);

	std::vector<__u8> pkt_data;
	for (int i=0; i < MAX_BUF_SIZE && i < info->pk_len ; i++)
		pkt_data.emplace_back(info->buf[i]);

	connection_data_map.insert_connection_data(checksum, pkt_data, (info->ingress&1) == 1);
	struct connection_data conn_data = connection_data_map.find(checksum);
	__u64 ingress_data_len = conn_data.ingress_data_len;
	__u64 egress_data_len = conn_data.egress_data_len;
	__u8 l7_proto = conn_data.proto.l7_protocol;

	int config_map_fd = bpf_object__find_map_fd_by_name(obj, "connection_config");
    if (config_map_fd < 0) {
        fprintf(stderr, "Error finding map\n");
        return 1;
    }

	struct connection_config_value value {1,1};

	if ((info->ingress != 0) && connection_data_map.should_stop_ingress_pkt_inspection(checksum))
	{
		if (bpf_map_lookup_elem(config_map_fd, &key, &value) != 0)
			bpf_map_update_elem(config_map_fd, &key, &value, BPF_ANY);
		 
		value.stop_ingress_pkt_data = 1;
		
		bpf_map_update_elem(config_map_fd, &key, &value, BPF_ANY);
	}
	if ((info->ingress == 0) && connection_data_map.should_stop_egress_pkt_inspection(checksum))
	{
		if (bpf_map_lookup_elem(config_map_fd, &key, &value) != 0)
			bpf_map_update_elem(config_map_fd, &key, &value, BPF_ANY);
		value.stop_egress_pkt_data = 1;
		
		bpf_map_update_elem(config_map_fd, &key, &value, BPF_ANY);
	}

	std::string temp_str = "";
	for (int i = 0; i<100 && i < pkt_data.size(); i++)
		temp_str += int_to_hex(pkt_data[i]) + " ";
	
	std::stringstream conn_summ;
	conn_summ << ((info->ingress&1) ? "Ingress" : "Egress") << " connection data local_ip: " << parse_ip(info->conn_key.local_ip, info->conn_key.local_port).c_str()
		<< ", remote_ip: " <<  parse_ip(info->conn_key.remote_ip, info->conn_key.remote_port).c_str() 
		<< ", data: " << temp_str.c_str() 
		<< ", ingress_len: " << ingress_data_len << ", egress_len: " << egress_data_len
		<< " , l7_proto: " << (l7_proto == 1 ? "SSH " : "Unknown ")
		<< ", key: " << checksum << "\n";

	FILE* file_output = fopen(output_file_path.c_str(), "a");
    if (!file_output) 
	{
        std::cerr << "Error opening file: " << output_file_path << std::endl;
        return 1;
    }

	fprintf(file_output, "CONN DATA: %s", conn_summ.str().c_str());
	fclose(file_output);

	// if (info->conn_key.local_ip == 0x201fea9 || info->conn_key.remote_ip == 0x201fea9 )
	// printf("%s connection data local_ip: %s, remote_ip: %s, data: %s, key: %lu\n",
	// 	   (info->ingress&1) ? "Ingress" : "Egress",
    //        parse_ip(info->conn_key.local_ip, info->conn_key.local_port).c_str(), 
	// 	   parse_ip(info->conn_key.remote_ip, info->conn_key.remote_port).c_str(), 
	// 	   temp_str.c_str(),
	// 	   checksum);

	return 0;

}

void start_pkt_info_ring_buff_polling()
{
	struct ring_buffer *rb = NULL;
    std::string ring_buff_path = "/sys/fs/bpf/pkt_info_ring_buff";
    int ring_buff_fd = bpf_obj_get(ring_buff_path.c_str());
    if (ring_buff_fd < 0) 
	{
        perror("bpf_obj_get");
		return;
    }

    rb = ring_buffer__new(ring_buff_fd, handle_event_pkt, NULL, NULL);
    if (!rb) 
	{
        perror("ring_buffer__new");
		return;
    }

	// std::cout << "starting the polling for info" <<std::endl;

    while (running) 
	{
        int err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err < 0) 
		{
            perror("ring_buffer__poll");
			return;
        }
    }
    ring_buffer__free(rb);
    if (unlink("/sys/fs/bpf/pkt_info_ring_buff") == -1 || close(ring_buff_fd) == -1)
        std::cout << "Unable to close map" << std::endl;
}

void start_conn_info_ring_buff_polling()
{
	struct ring_buffer *rb = NULL;
    std::string ring_buff_path = "/sys/fs/bpf/connection_setup_ring_buff";
    int ring_buff_fd = bpf_obj_get(ring_buff_path.c_str());
    if (ring_buff_fd < 0) 
	{
        perror("bpf_obj_get");
		return;
    }

    rb = ring_buffer__new(ring_buff_fd, handle_event_conn, NULL, NULL);
    if (!rb) 
	{
        perror("ring_buffer__new");
		return;
    }

	// std::cout << "starting the polling for info" <<std::endl;

    while (running) 
	{
        int err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err < 0) 
		{
            perror("ring_buffer__poll");
			return;
        }
    }
    ring_buffer__free(rb);
}

void start_conn_data_ring_buff_polling()
{
	struct ring_buffer *rb = NULL;
    std::string ring_buff_path = "/sys/fs/bpf/pkt_data_ring_buff";
    int ring_buff_fd = bpf_obj_get(ring_buff_path.c_str());
    if (ring_buff_fd < 0) 
	{
        perror("bpf_obj_get");
		return;
    }

    rb = ring_buffer__new(ring_buff_fd, handle_event_conn_data, NULL, NULL);
    if (!rb) 
	{
        perror("ring_buffer__new");
		return;
    }

	// std::cout << "starting the polling for info" <<std::endl;

    while (running) 
	{
        int err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err < 0) 
		{
            perror("ring_buffer__poll");
			return;
        }
    }
    ring_buffer__free(rb);
}

void unpin_maps(std::vector<std::string> maps_name)
{
	for (auto name : maps_name)
	{
		std::string ring_buff_path = "/sys/fs/bpf/" + name;
		int ring_buff_fd = bpf_obj_get(ring_buff_path.c_str());
		if (ring_buff_fd > 0) 
		{
			if (unlink(ring_buff_path.c_str()) == -1 || close(ring_buff_fd) == -1)
        		std::cout << "Unable to close map" << std::endl;
		}
		else
			std::cout << "no map for u" << std::endl;
	}
}	

__u32 rev_parse_ip(std::string ip)
{
	std::vector<int> values;
    std::istringstream iss(ip);
    std::string segment;

    while (std::getline(iss, segment, '.')) {
        values.push_back(std::stoi(segment));
    }

	if (values.size() != 4)
		return 0;

	__u32 ip_val = values[3];
	ip_val = (ip_val << 8) + values[2];
	ip_val = (ip_val << 8) + values[1];
	ip_val = (ip_val << 8) + values[0];

    return ip_val;
}

void block_ip_util(std::string ip)
{
	int config_map_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    if (config_map_fd < 0) 
	{
        fprintf(stderr, "Error finding map\n");
        return;
    }
	__u32 ip_int = rev_parse_ip(ip);
	__u8 value = 0;
	bpf_map_update_elem(config_map_fd, &ip_int, &value, BPF_ANY);
	return;
}

void unblock_ip_util(std::string ip)
{
	int config_map_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    if (config_map_fd < 0) 
	{
        fprintf(stderr, "Error finding map\n");
        return;
    }
	__u32 ip_int = rev_parse_ip(ip);
	bpf_map_delete_elem(config_map_fd, &ip_int);
	return;
}

int main(int argc, char* argv[])
{
    if (argc != 4) {
        std::cerr << "Usage: " << argv << " <data_file_path>" << " interface_seq " << "tc ok?" << std::endl;
        return 1;
    }

	output_file_path = argv[1];
	std::cout << "printing in file " << output_file_path << std::endl;

	int interface_seq = std::atoi(argv[2]);     //ip link show will give the interface number
    std::cout << "using interface index for: " << interface_seq <<std::endl; 

    char interface_name[256];
    if (if_indextoname(interface_seq, interface_name) == nullptr) {
        std::cerr << "Error: " << std::strerror(errno) << std::endl;
        return 1;
    }
    std::cout << "using interface name for: " << interface_name <<std::endl; 
	
	// todo make file if not exist

    std::string filename = "/home/ayush/testing/net_prot/conn_hooks.bpf.o";

	load_ebpf_obj(filename);
    if (obj == NULL)
    {
        std::cout << "Unable to load bpf object" << std::endl;
        return 1;
    }

    if (load_fentry_module("fentry_dev_queue_xmit") != 0)
    {
        std::cout << "Unable to load bpf fentry_dev_queue_xmit module" << std::endl;
	    bpf_object__close(obj);
        return 1;
    }

	if (load_fentry_module("fentry_tcp_connect") != 0)
    {
        std::cout << "Unable to load bpf fentry_tcp_connect module" << std::endl;
	    bpf_object__close(obj);
        return 1;
    }

	if (load_fentry_module("fentry_tcp_conn_request") != 0)
    {
        std::cout << "Unable to load bpf fentry_tcp_conn_request module" << std::endl;
	    bpf_object__close(obj);
        return 1;
    }

	if (load_fentry_module("fentry_tcp_close") != 0)
    {
        std::cout << "Unable to load bpf fentry_tcp_close module" << std::endl;
	    bpf_object__close(obj);
        return 1;
    }

	if (load_fentry_module("fentry_tcp_fin") != 0)
    {
        std::cout << "Unable to load bpf fentry_tcp_fin module" << std::endl;
	    bpf_object__close(obj);
        return 1;
    }

	struct bpf_program *ingress_prog;
    ingress_prog = bpf_object__find_program_by_name(obj, "kprobe_netif_receive_skb");
    if (!ingress_prog) {
        fprintf(stderr, "ERROR: finding program kprobe_netif_receive_skb failed\n");
		bpf_object__close(obj);
        return 1;
    }

    if (!bpf_program__attach_kprobe(ingress_prog, false, "__netif_receive_skb_core")) {
        fprintf(stderr, "ERROR: attaching kprobe to __netif_receive_skb_core failed\n");
		bpf_object__close(obj);
        return 1;
    }

	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_ingress, .ifindex = interface_seq,
			    .attach_point = BPF_TC_INGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, tc_hook_egress, .ifindex = interface_seq,
			    .attach_point = BPF_TC_EGRESS);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_ingress, .handle = 1, .priority = 1);
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, tc_opts_egress, .handle = 1, .priority = 1);

	int prog_fd_ingress = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_ingress"));
    if (prog_fd_ingress < 0) {
        fprintf(stderr, "ERROR: finding a program in BPF object file failed\n");
        return 1;
    }
	int prog_fd_egress = bpf_program__fd(bpf_object__find_program_by_name(obj, "tc_egress"));
    if (prog_fd_egress < 0) {
        fprintf(stderr, "ERROR: finding a program in BPF object file failed\n");
        return 1;
    }

	int err = bpf_tc_hook_create(&tc_hook_ingress);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create ingress TC hook: %d\n", err);
		return 1;
	}

	err = bpf_tc_hook_create(&tc_hook_egress);
	if (err && err != -EEXIST) {
		fprintf(stderr, "Failed to create egress TC hook: %d\n", err);
		return 1;
	}


	if (std::atoi(argv[3]) != 0)
	{
		if (std::atoi(argv[3]) == 2)
			sleep(10);
		tc_opts_ingress.prog_fd = prog_fd_ingress;
		if (bpf_tc_attach(&tc_hook_ingress, &tc_opts_ingress)) {
			fprintf(stderr, "ERROR: attaching BPF program to TC ingress point failed\n");
			return 1;
		}

		tc_opts_egress.prog_fd = prog_fd_egress;
		if (bpf_tc_attach(&tc_hook_egress, &tc_opts_egress)) {
			fprintf(stderr, "ERROR: attaching BPF program to TC egress point failed\n");
			return 1;
		}
	}

	std::thread pkt_info_thread(start_pkt_info_ring_buff_polling);
	std::thread conn_info_thread(start_conn_info_ring_buff_polling);
	std::thread conn_data_thread(start_conn_data_ring_buff_polling);

	while(1)
	{
		std::string input;
		std::cout << "> ";
		std::getline(std::cin, input);
		
		if (input == "exit")
		{
			break;
		}
		else if (input.compare(0, 5, "block") == 0)
		{
			std::regex ip_regex("(\\d+\\.\\d+\\.\\d+\\.\\d+)");
			std::smatch match;
			std::string::const_iterator searchStart(input.cbegin());
			while (std::regex_search(searchStart, input.cend(), match, ip_regex)) 
			{
				std::cout << "blocking connections for ip: " << match.str() << std::endl;
				block_ip_util(match.str());
				searchStart = match.suffix().first;
			}
		}
		else if (input.compare(0, 7, "unblock") == 0)
		{
			std::regex ip_regex("(\\d+\\.\\d+\\.\\d+\\.\\d+)");
			std::smatch match;
			std::string::const_iterator searchStart(input.cbegin());
			while (std::regex_search(searchStart, input.cend(), match, ip_regex)) 
			{
				std::cout << "unblocking connections for ip: " << match.str() << std::endl;
				unblock_ip_util(match.str());
				searchStart = match.suffix().first;
			}
		}
		else
		{
			std::cout << "retry :(" << std::endl;
		}

	}
    running = false;

	conn_info_thread.join();
	pkt_info_thread.join();
	conn_data_thread.join();

// cleanup:
	tc_opts_ingress.flags = tc_opts_ingress.prog_fd = tc_opts_ingress.prog_id = 0;
	bpf_tc_hook_destroy(&tc_hook_ingress);
	bpf_tc_hook_destroy(&tc_hook_egress);
	unpin_maps(std::vector<std::string>{"connection_config", "connection_setup_ring_buff", "pkt_info_ring_buff", "pkt_data_ring_buff", "blocked_ips"});
	bpf_object__close(obj);

	return 0;
}
