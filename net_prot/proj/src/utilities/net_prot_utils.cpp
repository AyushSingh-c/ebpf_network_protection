#include "utils.h"
#include "DnsLayer.h"
#include <ftw.h>
#include <net/if.h>
#include <dirent.h>
#include <unistd.h>
#include <algorithm>
#include <sys/types.h>

namespace
{
    std::string getProcessPath(pid_t pid) 
    {
        std::stringstream ss;
        ss << "/proc/" << pid << "/exe";
        char path[MAX_PROCESS_PATH_LEN];
        ssize_t len = readlink(ss.str().c_str(), path, sizeof(path) - 1);
        if (len != -1) {
            path[len] = '\0';
            return std::string(path);
        }
        return "";
    }

    pid_t getParentPid(pid_t pid) {
        std::stringstream ss;
        ss << "/proc/" << pid << "/stat";
        std::ifstream statFile(ss.str());
        if (statFile.is_open()) {
            std::string line;
            std::getline(statFile, line);
            std::istringstream iss(line);
            std::string token;
            for (int i = 0; i < 4; ++i) {
                iss >> token;
            }
            pid_t ppid;
            iss >> ppid;
            return ppid;
        }
        return -1;
    }

    void create_proc_dsu_with_path(utils::common::DisjointSetUnion& proc_dsu, const std::set<std::string>& isolated_bin_paths)
    {
        DIR* dir = opendir("/proc");
        if (dir) {
            struct dirent* entry;
            while ((entry = readdir(dir)) != nullptr) 
            {
                if (entry->d_type == DT_DIR) 
                {
                    pid_t pid = atoi(entry->d_name);
                    if (pid > 0 && isolated_bin_paths.find(getProcessPath(pid)) == isolated_bin_paths.end())
                    {
                        proc_dsu.unionSets(pid, getParentPid(pid));
                        // std::cout << "union of pid: " << pid << " and ppid: " << getParentPid(pid) << std::endl;
                    }
                }
            }
            closedir(dir);
        }
    }

    std::string get_path_from_dentry(process_info* info, pid_t pid)
    {
        std::string path = "";
        int starting_index = info->dentries_number - 1;
        for (int i = starting_index; i >= 0; i--)
        {
            if (info->dentries[i][0] == '\0' || info->dentries[i][0] == '/')
                continue;
            path += "/";
            for (int j = 0; j < info->dentry_sizes[i]; j++)
            {
                if (info->dentries[i][j] == '\0')
                    break;
                path += info->dentries[i][j];
            }
        }
        // std::cout << "dentry path: " << path << " and pid: " << pid << std::endl; 
        return path;
    }

    std::vector<ip_address_t> get_blocking_ips_from_dns(pcpp::Packet pkt, std::map<std::string, std::set<ip_address_t, utils::ip_addr_comparator>>& blocked_names)
    {
        std::vector<ip_address_t> blocking_ips{};
        for (auto* curLayer = pkt.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
        {
            if (curLayer->getProtocol() == pcpp::DNS)
            {
                pcpp::DnsLayer* dns_layer = dynamic_cast<pcpp::DnsLayer*>(curLayer);
                bool block_answers = false;
                std::string blocked_domain_name = "";
                pcpp::DnsQuery* curQuery = dns_layer->getFirstQuery();
                for (size_t i = 0; i < dns_layer->getQueryCount(); i++)
                {
                    if (curQuery != nullptr)
                    {
                        if( blocked_names.find(curQuery->getName()) != blocked_names.end())
                        {
                            blocked_domain_name = curQuery->getName();
                            block_answers = true;
                        }
                    }
                    curQuery = dns_layer->getNextQuery(curQuery);
                }
                if (block_answers)
                {
                    pcpp::DnsResource* curAnswer = dns_layer->getFirstAnswer();
                    for (size_t i = 0; i < dns_layer->getAnswerCount(); i++)
                    {
                        if (curAnswer != nullptr && curAnswer->getData() != nullptr)
                        {
                            if (curAnswer->getDnsType() == pcpp::DNS_TYPE_A)
                            {
                                ip_address_t block_ip = utils::net_specific::get_local_ip_struct_v4(curAnswer->getData()->castAs<pcpp::IPv4DnsResourceData>()->getIpAddress());
                                blocking_ips.emplace_back(block_ip);
                                blocked_names[blocked_domain_name].insert(block_ip);
                            }
                            if (curAnswer->getDnsType() == pcpp::DNS_TYPE_AAAA)
                            {
                                ip_address_t block_ip = utils::net_specific::get_local_ip_struct_v6(curAnswer->getData()->castAs<pcpp::IPv6DnsResourceData>()->getIpAddress());
                                blocking_ips.emplace_back(block_ip);
                                blocked_names[blocked_domain_name].insert(block_ip);
                            }
                            curAnswer = dns_layer->getNextAnswer(curAnswer);
                        }
                        else
                            break;
                    }
                }
                
            }
        }
        return blocking_ips;
    }    

    std::string serialise_ssl_data(const struct probe_SSL_data_t* data)
    {
        std::stringstream data_str;
        switch (data->rw)
        {
            case 0:
                data_str << "Read data: ";
                break;
            case 1:
                data_str << "Write data: ";
                break;
            case 2:
                data_str << "Handshake data: ";
                break;
            default:
                data_str << "Unknown data: ";
                break;
        }
        unsigned int buf_size = std::min(data->len, (__u32)MAX_BUF_SIZE);

        char buf[MAX_BUF_SIZE + 1] = {0};
        if (data->buf_filled == 1) {
            memcpy(buf, data->buf, buf_size);
        } else {
            buf_size = 0;
        }
        std::string ssl_data;
        for (size_t i = 0; i < MAX_BUF_SIZE && buf[i] != '\0'; ++i) 
        {
            if (isprint(static_cast<unsigned char>(buf[i]))) {
                ssl_data += buf[i];
            }
        }

        data_str << "timestamp(ns): " << data->timestamp_ns << ", pid: " << data->pid << ", tid: " << data->tid << ", uid: " << data->uid
            << ", len: " << data->len << ", buf_filled: " << (data->buf_filled == 1) << ", data: " << ssl_data << "\n";

        return data_str.str();
    }
}

connection_flow_map utils::net_prot_utils::connection_data_map(20000);
std::atomic<bool> utils::net_prot_utils::running = true;
bpf_object* utils::net_prot_utils::obj = NULL;
std::string utils::net_prot_utils::output_file_path = "/home/ayush/WD.Internal.PoC/Linux/ebpf/net_prot/proj/dump";
std::set<ip_lpm_key, utils::ip_lpm_key_comparator> utils::net_prot_utils::blocked_ips{};
std::set<__u16> utils::net_prot_utils::blocked_ports{};
std::set<std::string> utils::net_prot_utils::isolated_bin_paths{};
std::map<std::string, std::set<ip_address_t, utils::ip_addr_comparator>> utils::net_prot_utils::blocked_domains{};

int utils::net_prot_utils::handle_proc_info(void *ctx, void *data, size_t size)
{
    process_info *info = (process_info *)data;

    std::string path = get_path_from_dentry(info, info->pid);
        // std::cout << "parsing path: " << path << "for pid: " << info->pid << "with isolated pid size: " << isolated_bin_paths.size() << std::endl;
    int isolation_pids_map_fd = bpf_object__find_map_fd_by_name(obj, "isolation_pids");
    if (isolation_pids_map_fd < 0) 
    {
        fprintf(stderr, "Error finding isolation_pids map\n");
        return 1;
    }

    __u8 temp_value = 0;
    if (bpf_map_lookup_elem(isolation_pids_map_fd, &info->parent_pid, &temp_value) == 0 || isolated_bin_paths.find(path) != isolated_bin_paths.end())
    {
        bpf_map_update_elem(isolation_pids_map_fd, &info->pid, &temp_value, BPF_ANY);
            // std::cout << "pushing path: " << path << " pid: " << info->pid << std::endl;
    }
    return 0;
}

int utils::net_prot_utils::handle_event_pkt_info(void *ctx, void *data, size_t size)
{
    struct pkt_info *info = (pkt_info *)data;
    __u64 pkt_len = info->pk_len;
    char interface_name[256];
    if_indextoname(info->ifindex, interface_name);

    ip_address_t local_ip = (info->ingress&1) ? info->conn_key.dest_ip : info->conn_key.src_ip;
    __u16 local_port = (info->ingress&1) ? info->conn_key.dest_port : info->conn_key.src_port;
    ip_address_t remote_ip = (info->ingress&1) ? info->conn_key.src_ip : info->conn_key.dest_ip;
    __u16 remote_port = (info->ingress&1) ? info->conn_key.src_port : info->conn_key.dest_port;

    timeval timestamp = { static_cast<__time_t>(info->timestamp / 1000000), static_cast<__suseconds_t>(info->timestamp % 1000000) };
    protocols prot = {127, info->proto.l3_protocol, info->proto.l4_protocol, 127, 127, 127};

    struct connection_data temp = connection_data {
        utils::uuid::generate_uuid_random(),
        timestamp,
        connection_data_map.get_hash_key(
            local_ip, 
            local_port, 
            remote_ip, 
            remote_port),
        local_ip, 
        local_port, 
        remote_ip, 
        remote_port, 
        (info->ingress&1) ? prot : protocols{127, 127, 127, 127, 127, 127},
        (info->ingress&1) ? protocols{127, 127, 127, 127, 127, 127} : prot,
        0, // dummy
        interface_name,
        0,
        0,
        std::vector<struct packet_data>
        {
            packet_data
            {
                utils::uuid::generate_uuid_random(),
                timestamp,
                connection_data_map.get_hash_key(
                    local_ip, 
                    local_port, 
                    remote_ip, 
                    remote_port),
                info->proc,
                (info->ingress != 0),
                info->pk_len
            }
        },
        {},
        {}
    };

    connection_data_map.insert_pkt_info(temp.pkts[0], temp);

    struct connection_data conn_data = connection_data_map.sync_find(temp.checksum);
    __u64 len = conn_data.pkts.size();

    std::stringstream pkt_summ;
    pkt_summ << ((info->ingress == 0) ? "Egress" : "Ingress") << " packet src_ip: " << utils::common::parse_ip(info->conn_key.src_ip, info->conn_key.src_port).c_str()
        << ", dest_ip: " << utils::common::parse_ip(info->conn_key.dest_ip, info->conn_key.dest_port).c_str() << ", device name: " << interface_name << ", ip protocol: "
        << utils::net_specific::parse_ip_protocol(info->proto.l4_protocol).c_str() << ", pkt length: " << pkt_len << ", proc pid: " << std::to_string(info->proc).c_str()
        << ", pkts count: " << len << ", pkt uuid: " << conn_data.pkts[0].guid << ", connection uuid: " << conn_data.guid << "\n";

    FILE* file_output = fopen(output_file_path.c_str(), "a");
    if (!file_output) 
    {
        std::cerr << "Error opening file: " << output_file_path << std::endl;
        return 1;
    }

    fprintf(file_output, "PKT INFO: %s", pkt_summ.str().c_str());

    fclose(file_output);
    return 0;
}

int utils::net_prot_utils::handle_event_conn_setup(void *ctx, void *data, size_t size)
{
    struct connection_setup_info *info = (connection_setup_info *)data;
    char interface_name[256];
    if_indextoname(info->ifindex, interface_name);

    timeval timestamp = { static_cast<__time_t>(info->timestamp / 1000000), static_cast<__suseconds_t>(info->timestamp % 1000000) };
    protocols prot = {127, info->proto.l3_protocol, info->proto.l4_protocol, 127, 127, 127};

    ip_address_t local_ip = (info->conn_flow&1) ? info->conn_key.dest_ip : info->conn_key.src_ip;
    __u16 local_port = (info->conn_flow&1) ? info->conn_key.dest_port : info->conn_key.src_port;
    ip_address_t remote_ip = (info->conn_flow&1) ? info->conn_key.src_ip : info->conn_key.dest_ip;
    __u16 remote_port = (info->conn_flow&1) ? info->conn_key.src_port : info->conn_key.dest_port;

    struct connection_data temp = connection_data {
        utils::uuid::generate_uuid_random(),
        timestamp,
        connection_data_map.get_hash_key(
            local_ip, 
            local_port, 
            remote_ip, 
            remote_port),
        local_ip, 
        local_port, 
        remote_ip, 
        remote_port,
        (info->conn_flow&1) ? prot : protocols{127, 127, 127, 127, 127, 127},
        (info->conn_flow&1) ? protocols{127, 127, 127, 127, 127, 127} : prot,
        (info->conn_flow == 3),
        interface_name,
        0,
        0,
        {},
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
        fprintf(stderr, "Error finding connection_config map\n");
        bpf_object__close(obj);
        return 1;
    }

    std::stringstream conn_summ;
    struct connection_data conn_data;
    if ((info->conn_flow>>1)&1) //start conn
    {
        connection_data_map.insert_connection_setup(temp);
        conn_data = connection_data_map.sync_find(temp.checksum);
        bpf_map_update_elem(config_map_fd, &key, &value_start, BPF_ANY);
    }
    else //end conn
    {
        conn_data = connection_data_map.sync_find(temp.checksum);
        connection_data_map.remove_connection_setup(temp.checksum);
        bpf_map_delete_elem(config_map_fd, &key);
    }

    __u64 len = conn_data.pkts.size();

    conn_summ << ((info->conn_flow&1) ? "Incoming " : "Outgoing ") << (((info->conn_flow>>1)&1) ? "starting" : "ending") << " connection src_ip: "
        << utils::common::parse_ip(info->conn_key.src_ip, info->conn_key.src_port).c_str() << ", dest_ip: " << utils::common::parse_ip(info->conn_key.dest_ip, info->conn_key.dest_port).c_str() 
        << ", device id: " << info->ifindex << ", ip protocol: " << utils::net_specific::parse_ip_protocol(info->proto.l4_protocol).c_str() << ", proc pid: " << std::to_string(info->proc).c_str()
        << ", pkt count: " << len << ", connection guid: " << conn_data.guid << " connections maintained: " << connection_data_map.get_map_size() << "\n";

    FILE* file_output = fopen(output_file_path.c_str(), "a");
    if (!file_output) 
    {
        std::cerr << "Error opening file: " << output_file_path << std::endl;
        return 1;
    }

    fprintf(file_output, "CONN INFO: %s", conn_summ.str().c_str());
    fclose(file_output);
    return 0;
}

int utils::net_prot_utils::handle_event_pkt_data(void *ctx, void *data, size_t size)
{
    struct connection_kern_data *info = (connection_kern_data *)data;

    struct connection_config_key key = info->conn_key;

    size_t checksum = connection_data_map.get_hash_key(
        info->conn_key.local_ip, 
        info->conn_key.local_port, 
        info->conn_key.remote_ip, 
        info->conn_key.remote_port);

    std::vector<__u8> pkt_data;
    for (int i=0; i < MAX_BUF_SIZE && i < info->pk_len ; i++)
        pkt_data.emplace_back(info->buf[i]);

    std::string pkt_guid = utils::uuid::generate_uuid_random();
    timeval timestamp = { static_cast<__time_t>(info->timestamp / 1000000), static_cast<__suseconds_t>(info->timestamp % 1000000) };
    struct connection_data temp = connection_data {utils::uuid::generate_uuid_random()};
    connection_data_map.insert_connection_data(pkt_data, {pkt_guid, timestamp, checksum, 0, (info->ingress&1) == 1, info->pk_len}, temp);
    struct connection_data conn_data = connection_data_map.sync_find(checksum);
    __u64 ingress_data_len = conn_data.ingress_data_len;
    __u64 egress_data_len = conn_data.egress_data_len;
    std::stringstream pkt_parsed_info;
    if (info->ingress&1)
    {   
        if (conn_data.ingress_pkt_inspection_data.size() != 0)
        {
            int config_map_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
            if (config_map_fd < 0) 
            {
                fprintf(stderr, "Error finding blocked_ips map\n");
                return 1;
            }
            auto blocking_ips = get_blocking_ips_from_dns(conn_data.ingress_pkt_inspection_data[conn_data.ingress_pkt_inspection_data.size() - 1], blocked_domains);
            for (auto blocking_ip : blocking_ips)
            {
                auto key = ip_lpm_key{32, blocking_ip};
                int value = 0;
                bpf_map_update_elem(config_map_fd, &key, &value, BPF_ANY);
            }
            pkt_parsed_info << conn_data.ingress_pkt_inspection_data[conn_data.ingress_pkt_inspection_data.size() - 1].toString();
        }
    }
    else
    {
        if (conn_data.egress_pkt_inspection_data.size() != 0)
        {
            int config_map_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
            if (config_map_fd < 0) 
            {
                fprintf(stderr, "Error finding blocked_ips map\n");
                return 1;
            }
            auto blocking_ips = get_blocking_ips_from_dns(conn_data.egress_pkt_inspection_data[conn_data.egress_pkt_inspection_data.size() - 1], blocked_domains);
            for (auto blocking_ip : blocking_ips)
            {
                auto key = ip_lpm_key{32, blocking_ip};
                int value = 0;
                bpf_map_update_elem(config_map_fd, &key, &value, BPF_ANY);
            }
            pkt_parsed_info << conn_data.egress_pkt_inspection_data[conn_data.egress_pkt_inspection_data.size() - 1].toString();
        }
    }
    int config_map_fd = bpf_object__find_map_fd_by_name(obj, "connection_config");
    if (config_map_fd < 0) {
        fprintf(stderr, "Error finding connection_config map\n");
        return 1;
    }

    struct connection_config_value value {0, 0};

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
    for (int i = 0; i<200 && i < pkt_data.size(); i++)
        temp_str += "0x" + utils::common::int_to_hex(pkt_data[i]) + ", ";
    

    std::stringstream conn_summ;
    conn_summ << ((info->ingress&1) ? "Ingress" : "Egress") << " connection data local_ip: " << utils::common::parse_ip(info->conn_key.local_ip, info->conn_key.local_port).c_str()
        << ", remote_ip: " <<  utils::common::parse_ip(info->conn_key.remote_ip, info->conn_key.remote_port).c_str() 
        << ", pkt length: " << info->pk_len
        << ", data: " << temp_str.c_str() 
        << ", ingress_data_size: " << ingress_data_len << ", egress_data_size: " << egress_data_len
        << " , pkt_parsed info: " << pkt_parsed_info.str().c_str()
        << ", connection guid: " << conn_data.guid 
        << ", pkt guid: " << pkt_guid << "\n";

    FILE* file_output = fopen(output_file_path.c_str(), "a");
    if (!file_output) 
    {
        std::cerr << "Error opening file: " << output_file_path << std::endl;
        return 1;
    }

    fprintf(file_output, "CONN DATA: %s", conn_summ.str().c_str());
    fclose(file_output);
    return 0;
}

int utils::net_prot_utils::handle_event_ssl_data(void *ctx, void *data, size_t size)
{
    struct probe_SSL_data_t *ssl_data = (struct probe_SSL_data_t *)data;

    std::stringstream conn_summ;
    conn_summ << "process pid: " << ssl_data->pid << ", process name: " << getProcessPath(ssl_data->pid) << ", data: " << serialise_ssl_data(ssl_data);
    FILE* file_output = fopen(output_file_path.c_str(), "a");
    if (!file_output) 
    {
        std::cerr << "Error opening file: " << output_file_path << std::endl;
        return 1;
    }

    fprintf(file_output, "SSL DATA: %s", conn_summ.str().c_str());
    fclose(file_output);
    return 0;
}

void utils::net_prot_utils::start_ring_buff_polling(std::string ring_buff_path, Event_Handler handler)
{
    struct ring_buffer *rb = NULL;
    int ring_buff_fd = bpf_obj_get(ring_buff_path.c_str());
    if (ring_buff_fd < 0) 
    {
        perror("bpf_obj_get");
        return;
    }

    rb = ring_buffer__new(ring_buff_fd, handler, NULL, NULL);
    if (!rb) 
    {
        perror("ring_buffer__new");
        return;
    }

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
    if (unlink(ring_buff_path.c_str()) == -1 || close(ring_buff_fd) == -1)
        std::cout << "Unable to close map" << std::endl;
}

void utils::net_prot_utils::block_ip_util(std::string ip, uint8_t subnet)
{
    int config_map_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    if (config_map_fd < 0) 
    {
        fprintf(stderr, "Error finding blocked_ips map\n");
        return;
    }
    ip_lpm_key ip_int = utils::common::get_blocking_ip_key(ip, subnet);
    blocked_ips.insert(ip_int);
    __u8 value = 1;
    bpf_map_update_elem(config_map_fd, &ip_int, &value, BPF_ANY);
    return;
}

void utils::net_prot_utils::unblock_ip_util(std::string ip, uint8_t subnet)
{
    int config_map_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
    if (config_map_fd < 0) 
    {
        fprintf(stderr, "Error finding blocked_ips map\n");
        return;
    }
    ip_lpm_key ip_int = utils::common::get_blocking_ip_key(ip, subnet);
    blocked_ips.erase(ip_int);
    bpf_map_delete_elem(config_map_fd, &ip_int);
    return;
}

void utils::net_prot_utils::block_port_util(uint16_t port)
{
    int config_map_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ports");
    if (config_map_fd < 0) 
    {
        fprintf(stderr, "Error finding blocked_ports map\n");
        return;
    }
    __u8 value = 0;
    blocked_ports.insert(port);
    uint16_t tested_port = utils::common::get_correct_port(port);
    bpf_map_update_elem(config_map_fd, &tested_port, &value, BPF_ANY);
    return;
}

void utils::net_prot_utils::unblock_port_util(uint16_t port)
{
    int config_map_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ports");
    if (config_map_fd < 0) 
    {
        fprintf(stderr, "Error finding blocked_ports map\n");
        return;
    }
    blocked_ports.erase(port);
    uint16_t tested_port = utils::common::get_correct_port(port);
    bpf_map_delete_elem(config_map_fd, &tested_port);
    return;
}

void utils::net_prot_utils::block_domain_util(std::string domain)
{
    blocked_domains.insert({domain, std::set<ip_address_t, utils::ip_addr_comparator>{}});
}

void utils::net_prot_utils::unblock_domain_util(std::string domain)
{
    auto it = blocked_domains.find(domain);
    if (it != blocked_domains.end()) 
    {
        for (auto& ip : it->second)
        {
            int config_map_fd = bpf_object__find_map_fd_by_name(obj, "blocked_ips");
            if (config_map_fd < 0) 
            {
                fprintf(stderr, "Error finding blocked_ips map\n");
                return;
            }
            ip_lpm_key ip_int = {32, ip};
            if (blocked_ips.find(ip_int) == blocked_ips.end())
            {
                bpf_map_delete_elem(config_map_fd, &ip_int);
            }
        }
        blocked_domains.erase(it);
    } 
}

void utils::net_prot_utils::add_isolation_path(std::string path)
{
    // std::cout << "adding path " << path << " to isolation" << std::endl;
    isolated_bin_paths.insert(path);
}

void utils::net_prot_utils::remove_isolation_path(std::string path)
{
    // std::cout << "removing path " << path << " to isolation" << std::endl;
    isolated_bin_paths.erase(path);
}

void utils::net_prot_utils::add_pid_in_isolation_pids_map(uint64_t pid)
{
    // std::cout << "adding pid " << pid << " to isolation map path: " << getProcessPath(pid) << std::endl;
    int isolation_pids_map_fd = bpf_object__find_map_fd_by_name(obj, "isolation_pids");
    if (isolation_pids_map_fd < 0) 
    {
        fprintf(stderr, "Error finding isolation_pids map\n");
        return;
    }
    __u8 value = 0;
    bpf_map_update_elem(isolation_pids_map_fd, &pid, &value, BPF_ANY);
    return;
}

void utils::net_prot_utils::remove_pid_in_isolation_pids_map(uint64_t pid)
{
    // std::cout << "removing pid " << pid << " to isolation map" << std::endl;
    int isolation_pids_map_fd = bpf_object__find_map_fd_by_name(obj, "isolation_pids");
    if (isolation_pids_map_fd < 0) 
    {
        fprintf(stderr, "Error finding isolation_pids map\n");
        return;
    }
    bpf_map_delete_elem(isolation_pids_map_fd, &pid);
    return;
}

void utils::net_prot_utils::configure_isolation(bool enable)
{
    int config_map_fd = bpf_object__find_map_fd_by_name(obj, "config_map");
    if (config_map_fd < 0) {
        fprintf(stderr, "Error finding config_map map\n");
        return ;
    }

    struct net_prot_config curr_value;
    int config_index = 0;
    if (bpf_map_lookup_elem(config_map_fd, &config_index, &curr_value))
    {
        fprintf(stderr, "Error finding config_map map\n");
        return ;
    }


    if (enable)
    {
        curr_value.isolation= 1;
        if (bpf_map_update_elem(config_map_fd, &config_index, &curr_value, BPF_ANY))
        {
            fprintf(stderr, "Error finding config_map map\n");
            return ;
        }
    }
    else
    {
        curr_value.isolation = 0;
        if (bpf_map_update_elem(config_map_fd, &config_index, &curr_value, BPF_ANY))
        {
            fprintf(stderr, "Error finding config_map map\n");
            return ;
        }
    }
}

void utils::net_prot_utils::reset_isolated_pid_map() 
{
    utils::common::DisjointSetUnion proc_dsu = utils::common::DisjointSetUnion(MAX_PROC_COUNT);
    create_proc_dsu_with_path(proc_dsu, isolated_bin_paths);

    DIR* dir = opendir("/proc");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) 
        {
            if (entry->d_type == DT_DIR) 
            {
                pid_t pid = atoi(entry->d_name);
                if (pid > 0)
                {
                    __s64 root = proc_dsu.find(pid);
                    if (root != -1 && isolated_bin_paths.find(getProcessPath(root)) != isolated_bin_paths.end())
                    {
                        add_pid_in_isolation_pids_map(pid);
                    }
                    else
                        remove_pid_in_isolation_pids_map(pid);
                }
            }
        }
        closedir(dir);
    }
    return ;
}

void utils::net_prot_utils::add_honeypot_endpoint(struct redirection_endpoint_mac base_end_pt, struct redirection_endpoint_mac mock_end_pt)
{
    int config_map_fd = bpf_object__find_map_fd_by_name(obj, "redirect_endpoints");
    if (config_map_fd < 0) 
    {
        fprintf(stderr, "Error finding redirect_endpoints map\n");
        return;
    }
    bpf_map_update_elem(config_map_fd, &base_end_pt.endpoint, &mock_end_pt, BPF_ANY);

    config_map_fd = bpf_object__find_map_fd_by_name(obj, "reverse_redirect_endpoints");
    if (config_map_fd < 0) 
    {
        fprintf(stderr, "Error finding reverse_redirect_endpoints map\n");
        return;
    }
    bpf_map_update_elem(config_map_fd, &mock_end_pt.endpoint, &base_end_pt, BPF_ANY);
    return;
}

void utils::net_prot_utils::configure_ip_for_redirection(struct ip_lpm_key ip, bool redirect)
{
    int config_map_fd = bpf_object__find_map_fd_by_name(obj, "redirect_ips");
    if (config_map_fd < 0) 
    {
        fprintf(stderr, "Error finding redirect_ips map\n");
        return;
    }
    if (redirect)
    {
        __u8 value = 1;
        bpf_map_update_elem(config_map_fd, &ip, &value, BPF_ANY);
    }
    else
    {
        __u8 value = 1;
        if (bpf_map_lookup_elem(config_map_fd, &ip, &value))
        {
            std::cout << "bad delete" 
            << int(ip.addr.addr.ipv4[0]) << "." << int(ip.addr.addr.ipv4[1]) << "." << int(ip.addr.addr.ipv4[2]) << "." << int(ip.addr.addr.ipv4[3])
            << ip.prefix_len << std::endl;
        }
        bpf_map_delete_elem(config_map_fd, &ip);
    }
    return;
}