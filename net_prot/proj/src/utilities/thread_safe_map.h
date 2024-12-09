#pragma once

#include "src/conn_info.h"
#include "src/utilities/utils.h"
#include "pcapplusplus/Packet++/header/Packet.h"

#include <map>
#include <mutex>
#include <set>
#include <thread>
#include <atomic>
#include <cstdint>
#include <sys/time.h>

struct packet_data
{
	std::string guid;
    timeval timestamp;
	size_t checksum;
    __u64 proc;
    bool ingress;
    unsigned int pk_len;
};

struct connection_data
{
	std::string guid;
	timeval timestamp;
	size_t checksum;
	ip_address_t local_ip;
    __u16 local_port;
    ip_address_t remote_ip;
    __u16 remote_port;
    struct protocols ingress_proto{127, 127, 127, 127, 127, 127};
    struct protocols egress_proto{127, 127, 127, 127, 127, 127};
	bool incoming;
    std::string dev_name;
	__u64 ingress_data_len;
	__u64 egress_data_len;
	std::vector<struct packet_data> pkts;
	std::vector<pcpp::Packet> ingress_pkt_inspection_data; 
	std::vector<pcpp::Packet> egress_pkt_inspection_data; 
};

class connection_flow_map
{
public:
	connection_flow_map(size_t maxSize) : maxSize(maxSize) {}

	void insert_pkt_info(const packet_data& info, const connection_data& dummy_connection_data)
	{
		std::unique_lock<std::mutex> lock(mtx);
		auto it = flow_map.find(info.checksum);
		if (it != flow_map.end()) 
		{
			flow_map[info.checksum].pkts.push_back(info);
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
			flow_map.insert({info.checksum, dummy_connection_data});
			channel_less_proto.insert({info.timestamp.tv_sec, info.checksum});
		}
	}

	void insert_connection_data(std::vector<__u8>& data, const packet_data& info, const connection_data& dummy_connection_data)
	{
		pcpp::RawPacket rawPacket(reinterpret_cast<uint8_t*>(data.data()), data.size(), info.timestamp, false, pcpp::LINKTYPE_ETHERNET);	
		pcpp::Packet parsedPacket(&rawPacket);

		std::unique_lock<std::mutex> lock(mtx);

		auto it = flow_map.find(info.checksum);
		if (it == flow_map.end())
		{
			flow_map.insert({info.checksum, dummy_connection_data});
		}
		it = flow_map.find(info.checksum);
        if (it != flow_map.end()) 
		{
			if (info.ingress)
			{
				if (flow_map[info.checksum].ingress_data_len < MAX_BUF_SIZE)
				{
					flow_map[info.checksum].ingress_pkt_inspection_data.emplace_back(parsedPacket);
					flow_map[info.checksum].ingress_data_len += data.size();
				}

				for (auto* curLayer = parsedPacket.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
				{
					auto proto_type = curLayer->getProtocol();
					switch (curLayer->getLayerLevel())
					{
						case 2:
							flow_map[info.checksum].ingress_proto.l2_protocol = static_cast<int>(proto_type);
							break;
						case 3:
							flow_map[info.checksum].ingress_proto.l3_protocol = static_cast<int>(proto_type);
							break;
						case 4:
							flow_map[info.checksum].ingress_proto.l4_protocol = static_cast<int>(proto_type);
							break;
						case 5:
							flow_map[info.checksum].ingress_proto.l5_protocol = static_cast<int>(proto_type);
							break;
						case 6:
							flow_map[info.checksum].ingress_proto.l6_protocol = static_cast<int>(proto_type);
							break;
						case 7:
							flow_map[info.checksum].ingress_proto.l7_protocol = static_cast<int>(proto_type);
							break;
					}
				}
			}
			else
			{
				if (flow_map[info.checksum].egress_data_len < MAX_BUF_SIZE)
				{
					flow_map[info.checksum].egress_pkt_inspection_data.emplace_back(parsedPacket);
					flow_map[info.checksum].egress_data_len += data.size();
				}
				for (auto* curLayer = parsedPacket.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
				{
					auto proto_type = curLayer->getProtocol();
					switch (curLayer->getLayerLevel())
					{
						case 2:
							flow_map[info.checksum].egress_proto.l2_protocol = static_cast<int>(proto_type);
							break;
						case 3:
							flow_map[info.checksum].egress_proto.l3_protocol = static_cast<int>(proto_type);
							break;
						case 4:
							flow_map[info.checksum].egress_proto.l4_protocol = static_cast<int>(proto_type);
							break;
						case 5:
							flow_map[info.checksum].egress_proto.l5_protocol = static_cast<int>(proto_type);
							break;
						case 6:
							flow_map[info.checksum].egress_proto.l6_protocol = static_cast<int>(proto_type);
							break;
						case 7:
							flow_map[info.checksum].egress_proto.l7_protocol = static_cast<int>(proto_type);
							break;
					}
				}
			}
		}
	}

	void insert_connection_setup(struct connection_data& data)
	{
		std::unique_lock<std::mutex> lock(mtx);
		auto it = flow_map.find(data.checksum);
        if (it != flow_map.end()) 
		{
			flow_map[data.checksum].incoming = data.incoming;

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
			if (is_channel_proto(data.ingress_proto.l4_protocol) && is_channel_proto(data.egress_proto.l4_protocol))
			{
				channel_proto.insert({data.timestamp.tv_sec, data.checksum});
			}
			else
			{
				channel_less_proto.insert({data.timestamp.tv_sec, data.checksum});
			}
        }
	}

	void remove_connection_setup(size_t key)
	{
		std::unique_lock<std::mutex> lock(mtx);
		struct connection_data data = flow_map[key];
		channel_proto.erase({data.timestamp.tv_sec, data.checksum});
		channel_less_proto.erase({data.timestamp.tv_sec, data.checksum});
		flow_map.erase(data.checksum);
	}

	bool should_stop_ingress_pkt_inspection(size_t key)
	{
		std::unique_lock<std::mutex> lock(mtx);
		auto it = flow_map.find(key);
        if (it != flow_map.end()) 
			return flow_map[key].ingress_data_len >= MAX_BUF_SIZE;
		return false;
	}

	bool should_stop_egress_pkt_inspection(size_t key)
	{
		std::unique_lock<std::mutex> lock(mtx);
		auto it = flow_map.find(key);
        if (it != flow_map.end()) 
			return flow_map[key].egress_data_len >= MAX_BUF_SIZE;
		return false;
	}

	size_t get_hash_key(ip_address_t local_ip, __u16 local_port, ip_address_t remote_ip, __u16 remote_port)
	{
		std::string local = "";
		if (local_ip.version == IPV4)
		{
			for (int i = 0; i < IPV4_ADDR_LEN; i++)
				local += std::to_string(local_ip.addr.ipv4[i]);
			local += std::to_string(local_port);
		}
		else
		{
			for (int i = 0; i < IPV6_ADDR_LEN; i++)
				local += std::to_string(local_ip.addr.ipv6[i]);
			local += std::to_string(local_port);
		}
		std::string remote = "";
		if (remote_ip.version == IPV4)
		{
			for (int i = 0; i < IPV4_ADDR_LEN; i++)
				remote += std::to_string(remote_ip.addr.ipv4[i]);
			remote += std::to_string(remote_port);
		}
		else
		{
			for (int i = 0; i < IPV6_ADDR_LEN; i++)
				remote += std::to_string(remote_ip.addr.ipv6[i]);
			remote += std::to_string(remote_port);
		}
		return hasher(local + remote);
	}

	size_t get_map_size()
	{
		return flow_map.size();
	}

	const struct connection_data find(size_t key)
	{
		auto it = flow_map.find(key);
        if (it != flow_map.end()) 
			return flow_map[key];
		return {};
	}

	const struct connection_data sync_find(size_t key)
	{
		std::unique_lock<std::mutex> lock(mtx);
		auto it = flow_map.find(key);
        if (it != flow_map.end()) 
			return flow_map[key];
		return {};
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
		return l4_protocol == pcpp::TCP;
		//return l4_protocol == pcpp::TCP || l4_protocol == pcpp::COTP || l4_protocol == pcpp::TPKT;  - other connection based protocols??
	}
};