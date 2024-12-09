#pragma once

#include <argp.h>
#include <string>
#include <iostream>
#include <cctype>
#include <fstream>
#include <sstream>
#include <unistd.h>
#include <cstring>
#include <thread>

#include "thread_safe_map.h"
#include "IpAddress.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

typedef unsigned int __u32;
typedef unsigned char __u8;
typedef int (*Event_Handler)(void *ctx, void *data, size_t size);

// namespace
// {
//     // Function declarations
//     void block_ipv4(const std::string &ip) { std::cout << "Blocking IPv4: " << ip << std::endl; }
//     void unblock_ipv4(const std::string &ip) { std::cout << "Unblocking IPv4: " << ip << std::endl; }
//     void block_ipv6(const std::string &ip) { std::cout << "Blocking IPv6: " << ip << std::endl; }
//     void unblock_ipv6(const std::string &ip) { std::cout << "Unblocking IPv6: " << ip << std::endl; }
//     void block_port(int port) { std::cout << "Blocking port: " << port << std::endl; }
//     void unblock_port(int port) { std::cout << "Unblocking port: " << port << std::endl; }
//     void block_domain(const std::string &domain) { std::cout << "Blocking domain: " << domain << std::endl; }
//     void unblock_domain(const std::string &domain) { std::cout << "Unblocking domain: " << domain << std::endl; }
//     void start_isolation() { std::cout << "Starting isolation" << std::endl; }
//     void end_isolation() { std::cout << "Ending isolation" << std::endl; }
//     void add_isolation_path(const std::string &path) { std::cout << "Adding isolation path: " << path << std::endl; }
//     void remove_isolation_path(const std::string &path) { std::cout << "Removing isolation path: " << path << std::endl; }
//     void enable_tc() { std::cout << "Enabling tc" << std::endl; }
//     void disable_tc() { std::cout << "Disabling tc" << std::endl; }
//     void enable_redirection() { std::cout << "Enabling redirection" << std::endl; }
//     void disable_redirection() { std::cout << "Disabling redirection" << std::endl; }
//     void enable_uprobes() { std::cout << "Enabling uprobes on cryptography .so" << std::endl; }
//     void disable_uprobes() { std::cout << "Disabling uprobes on cryptography .so" << std::endl; }
//     void log_malicious_connection(const std::string &local_ip, int local_port, const std::string &remote_ip, int remote_port, int redirection_socket_id) {
//         std::cout << "Logging malicious connection: "
//                 << "Local IP: " << local_ip
//                 << ", Local Port: " << local_port
//                 << ", Remote IP: " << remote_ip
//                 << ", Remote Port: " << remote_port
//                 << ", Redirection Socket ID: " << redirection_socket_id
//                 << std::endl;
//     }
//     void enable_throttling(int level) { std::cout << "Enabling throttling level: " << level << std::endl; }
//     void set_output_dir_tsv(const std::string &path) { std::cout << "Setting TSV output directory: " << path << std::endl; }
//     void set_output_dir_json(const std::string &path) { std::cout << "Setting JSON output directory: " << path << std::endl; }
//     void set_verbose() { std::cout << "Enabling verbose output" << std::endl; }

// }

namespace utils::common
{
    __u16 get_correct_port(__u16 port);
    std::string parse_ip(ip_address_t ip, __u16 port);
    ip_lpm_key get_blocking_ip_key(std::string ip, uint8_t subnet);
    std::string int_to_hex(int value);

    class DisjointSetUnion {
    private:
        std::vector<__s64> parent;
        std::vector<__s64> rank;
        int size;

    public:
        // Constructor to initialize the DSU structure
        DisjointSetUnion(int length) 
        {
            size = length;
            parent.resize(size);
            rank.resize(size, 0);
            for (int i = 0; i < size; ++i) {
                parent[i] = i; // Each element is its own parent initially
            }
        }

        // Find with path compression
        __s64 find(__s64 x) {
            if (x >= size)
                return -1;
            if (parent[x] != x) {
                parent[x] = find(parent[x]); // Path compression
            }
            return parent[x];
        }

        // Union by rank
        void unionSets(__s64 x, __s64 y) {
            __s64 rootX = find(x);
            __s64 rootY = find(y);

            if (rootX != rootY && rootX != -1 && rootY != -1) {
                // Union by rank
                if (rank[rootX] < rank[rootY]) {
                    parent[rootX] = rootY;
                } else if (rank[rootX] > rank[rootY]) {
                    parent[rootY] = rootX;
                } else {
                    parent[rootY] = rootX;
                    rank[rootX]++;
                }
            }
        }
    };
}

namespace utils::bpf
{
    void list_prog(struct bpf_object *obj);
    struct bpf_object* load_ebpf_obj(std::string filename);
    int load_fentry_module(struct bpf_object *obj, std::string module_name);
    int load_kprobe_module(struct bpf_object *obj, std::string module_name, std::string hook_name);
    int load_tracepoint_module(struct bpf_object *obj, std::string module_name, std::string submodule_name, std::string tracepoint_name);
    std::vector<bpf_tc_hook> load_tc_for_interface(struct bpf_object *obj, int interface_seq, bool should_load);
    int load_uprobe_on_binary(struct bpf_object *obj, const std::string& bin_path, const uint64_t& hook_offset, const std::string& module_name, bool is_retprobe);
    void unpin_maps(std::vector<std::string> maps_name);
}

namespace utils::uuid
{
    std::string generate_uuid_random();
}

// namespace utils::cli_parser
// {
//     static struct argp_option options[] = 
//     {
//         {"block-ipv4", 'i', "IP", 0, "Block an IPv4 address"},
//         {"unblock-ipv4", 'I', "IP", 0, "Unblock an IPv4 address"},
//         {"block-ipv6", 'j', "IP", 0, "Block an IPv6 address"},
//         {"unblock-ipv6", 'J', "IP", 0, "Unblock an IPv6 address"},
//         {"block-port", 'p', "PORT", 0, "Block a port"},
//         {"unblock-port", 'P', "PORT", 0, "Unblock a port"},
//         {"block-domain", 'd', "Domain Name", 0, "Block a domain"},
//         {"unblock-domain", 'D', "Domain Name", 0, "Unblock a domain"},
//         {"start-isolation", 's', 0, 0, "Start isolation"},
//         {"end-isolation", 'S', 0, 0, "End isolation"},
//         {"add-isolation-path", 'a', "Path", 0, "Add a path to isolation"},
//         {"remove-isolation-path", 'A', "Path", 0, "Remove a path from isolation"},
//         {"enable-tc", 't', 0, 0, "Enable tc"},
//         {"disable-tc", 'T', 0, 0, "Disable tc"},
//         {"enable-redirection", 'r', 0, 0, "Enable redirection"},
//         {"disable-redirection", 'R', 0, 0, "Disable redirection"},
//         {"enable-uprobes", 'u', 0, 0, "Enable uprobes on cryptography .so"},
//         {"disable-uprobes", 'U', 0, 0, "Disable uprobes on cryptography .so"},
//         {"malicious-connection", 'm', "LOCAL_IP LOCAL_PORT REMOTE_IP REMOTE_PORT REDIRECTION_SOCKET_ID", 0, "Redirect pkts from malicious connection - can also be used to block a connection id socket id is -1"},
//         {"enable-throttling", 'l', "LEVEL", 0, "Throttling level from 0-4. 0 is no throttling"},
//         {"output-dir-tsv", 'o', "Output TSV Dir Path", 0, "Output TSV Log Dir path"},
//         {"output-dir-json", 'O', "Output JSON Dir Path", 0, "Output JSON Dir path"},
// 	    {"verbose", 'v', NULL, 0, "Verbose debug output"},
// 	    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
//         {0}
//     };
    
//     static error_t parse_opt(int key, char *arg, struct argp_state *state) 
//     {
//         switch (key) {
//             case 'i':
//                 block_ipv4(arg);
//                 break;
//             case 'I':
//                 unblock_ipv4(arg);
//                 break;
//             case 'j':
//                 block_ipv6(arg);
//                 break;
//             case 'J':
//                 unblock_ipv6(arg);
//                 break;
//             case 'p':
//                 block_port(std::stoi(arg));
//                 break;
//             case 'P':
//                 unblock_port(std::stoi(arg));
//                 break;
//             case 'd':
//                 block_domain(arg);
//                 break;
//             case 'D':
//                 unblock_domain(arg);
//                 break;
//             case 's':
//                 start_isolation();
//                 break;
//             case 'S':
//                 end_isolation();
//                 break;
//             case 'a':
//                 add_isolation_path(arg);
//                 break;
//             case 'A':
//                 remove_isolation_path(arg);
//                 break;
//             case 't':
//                 enable_tc();
//                 break;
//             case 'T':
//                 disable_tc();
//                 break;
//             case 'r':
//                 enable_redirection();
//                 break;
//             case 'R':
//                 disable_redirection();
//                 break;
//             case 'u':
//                 enable_uprobes();
//                 break;
//             case 'U':
//                 disable_uprobes();
//                 break;
//             case 'm':
//                 if (state->next + 4 < state->argc) {
//                     std::string local_ip = arg;
//                     int local_port = std::stoi(state->argv[state->next]);
//                     std::string remote_ip = state->argv[state->next + 1];
//                     int remote_port = std::stoi(state->argv[state->next + 2]);
//                     int redirection_socket_id = std::stoi(state->argv[state->next + 3]);
//                     state->next += 4;
//                     log_malicious_connection(local_ip, local_port, remote_ip, remote_port, redirection_socket_id);
//                 } else {
//                     argp_usage(state);
//                 }
//                 break;
//             case 'l':
//                 enable_throttling(std::stoi(arg));
//                 break;
//             case 'o':
//                 set_output_dir_tsv(arg);
//                 break;
//             case 'O':
//                 set_output_dir_json(arg);
//                 break;
//             case 'v':
//                 set_verbose();
//                 break;
//             case ARGP_KEY_ARG:
//                 if (state->arg_num == 0) {
//                     std::cerr << "Unknown command: " << arg << std::endl;
//                     argp_usage(state);
//                 }
//                 break;
//             case ARGP_KEY_END:
//                 if (state->arg_num < 1) {
//                     argp_usage(state);
//                 }
//                 break;
//             default:
//                 return ARGP_ERR_UNKNOWN;
//         }
//         return 0;
//     }

//     static struct argp argp = {options, parse_opt, args_doc, doc};

//     static void parse_args(int argc, char **argv) 
//     {
//         while (true) 
//         {
//             std::cout << "Enter command: ";
//             std::string input;
//             std::getline(std::cin, input);

//             // Split input into arguments
//             std::vector<char *> args;
//             char *arg = strtok(&input[0], " ");
//             while (arg != nullptr) {
//                 args.push_back(arg);
//                 arg = strtok(nullptr, " ");
//             }

//             // Prepare arguments for argp_parse
//             int argc = args.size();
//             char **argv = args.data();

//             // Parse our arguments
//             argp_parse(&argp, argc, argv, 0, 0, nullptr);
//         }
//     }
// }

namespace utils::net_specific
{
    std::string parse_ip_protocol(__u8 proto);
    ip_address_t get_local_ip_struct_v4(pcpp::IPv4Address ip);
    ip_address_t get_local_ip_struct_v6(pcpp::IPv6Address ip);
    struct redirection_endpoint_mac get_redirection_endpoint(std::string ip, __u16 port);
}

namespace utils
{
    struct ip_lpm_key_comparator 
    {
        bool operator()(const ip_lpm_key& lhs, const ip_lpm_key& rhs) const 
        {
            if (lhs.prefix_len != rhs.prefix_len) 
            {
                return lhs.prefix_len < rhs.prefix_len;
            }
            if (lhs.addr.version != rhs.addr.version) 
            {
                return lhs.addr.version < rhs.addr.version;
            }
            if (lhs.addr.version == IPV4) 
            {
                return std::memcmp(lhs.addr.addr.ipv4, rhs.addr.addr.ipv4, IPV4_ADDR_LEN) < 0;
            } 
            else 
            {
                return std::memcmp(lhs.addr.addr.ipv6, rhs.addr.addr.ipv6, IPV6_ADDR_LEN * sizeof(uint16_t)) < 0;
            }
        }
    };

    struct ip_addr_comparator 
    {
        bool operator()(const ip_address_t& lhs, const ip_address_t& rhs) const 
        {
            if (lhs.version != rhs.version) 
            {
                return lhs.version < rhs.version;
            }
            if (lhs.version == IPV4) 
            {
                return std::memcmp(lhs.addr.ipv4, rhs.addr.ipv4, IPV4_ADDR_LEN) < 0;
            } 
            else 
            {
                return std::memcmp(lhs.addr.ipv6, rhs.addr.ipv6, IPV6_ADDR_LEN * sizeof(uint16_t)) < 0;
            }
        }
    };

    class net_prot_utils
    {
        static class connection_flow_map connection_data_map;
        static std::string output_file_path;
        static std::set<ip_lpm_key, ip_lpm_key_comparator> blocked_ips;
        static std::set<uint16_t> blocked_ports;
        static std::map<std::string, std::set<ip_address_t, ip_addr_comparator>> blocked_domains;
        static std::set<std::string> isolated_bin_paths;

    public:
        static struct bpf_object *obj;
        static std::atomic<bool> running;
        static void init()
        {
            connection_flow_map connection_data_map(20000);
            running = true;
            obj = NULL;
            output_file_path = "/home/ayush/WD.Internal.PoC/Linux/ebpf/net_prot/proj/dump"; //real
        }

        static int handle_proc_info(void *ctx, void *data, size_t size);
        static int handle_event_pkt_info(void *ctx, void *data, size_t size);
        static int handle_event_conn_setup(void *ctx, void *data, size_t size);
        static int handle_event_pkt_data(void *ctx, void *data, size_t size);
        static int handle_event_ssl_data(void *ctx, void *data, size_t size);

        static void start_ring_buff_polling(std::string ring_buff_path, Event_Handler handler);

        static void block_ip_util(std::string ip, uint8_t subnet);
        static void unblock_ip_util(std::string ip, uint8_t subnet);
        static void block_port_util(uint16_t port);
        static void unblock_port_util(uint16_t port);
        static void block_domain_util(std::string domain);
        static void unblock_domain_util(std::string domain);

        static void add_isolation_path(std::string path);
        static void remove_isolation_path(std::string path);

        static void remove_pid_in_isolation_pids_map(uint64_t pid);
        static void add_pid_in_isolation_pids_map(uint64_t pid);
        static void reset_isolated_pid_map();
        static void configure_isolation(bool enable);

        static void add_honeypot_endpoint(struct redirection_endpoint_mac base_end_pt, struct redirection_endpoint_mac mock_end_pt);
        static void configure_ip_for_redirection(struct ip_lpm_key ip, bool redirect);

        static std::string get_output_file_path()
        {
            return output_file_path;
        }
    };
}