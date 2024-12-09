#include "utils.h"
#include <iostream>
#include <cstring>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>

namespace 
{
    void get_interface_info(const std::string& ipAddress, struct redirection_endpoint_mac& end_pt) 
    {
        struct ifaddrs *ifaddr, *ifa;
        int family, s;
        char host[NI_MAXHOST];

        if (getifaddrs(&ifaddr) == -1) {
            perror("getifaddrs");
            return;
        }

        for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == nullptr)
                continue;

            family = ifa->ifa_addr->sa_family;

            if (family == AF_INET) 
            {
                s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                host, NI_MAXHOST, nullptr, 0, NI_NUMERICHOST);
                if (s != 0) {
                    std::cerr << "getnameinfo() failed: " << gai_strerror(s) << std::endl;
                    continue;
                }

                if (ipAddress == host) 
                {
                    // Get the interface index
                    int if_index = if_nametoindex(ifa->ifa_name);
                    // Get the MAC address
                    int fd = socket(AF_INET, SOCK_DGRAM, 0);
                    if (fd == -1) {
                        perror("socket");
                        continue;
                    }

                    struct ifreq ifr;
                    std::strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ-1);
                    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
                        perror("ioctl");
                        close(fd);
                        continue;
                    }

                    close(fd);

                    unsigned char *mac = reinterpret_cast<unsigned char *>(ifr.ifr_hwaddr.sa_data);
                    for (int i = 0; i < 6; ++i) 
                    {
                        end_pt.mac_addr[i] = mac[i];
                    }
                    end_pt.interface_index = if_index;
                }
            }
        }

        freeifaddrs(ifaddr);
    }
}

ip_address_t utils::net_specific::get_local_ip_struct_v4(pcpp::IPv4Address ip)
{
    ip_address_t ret_ip{};
    ret_ip.version = IPV4;
    std::array<uint8_t, 4> byte_addr = ip.toByteArray();
    for (auto i = 0; i < IPV4_ADDR_LEN; i++)
    {
        ret_ip.addr.ipv4[i] = byte_addr[i];
    }
    return ret_ip;
}

ip_address_t utils::net_specific::get_local_ip_struct_v6(pcpp::IPv6Address ip)
{
    ip_address_t ret_ip{};
    ret_ip.version = IPV6;
    std::array<uint8_t, 16> byte_addr = ip.toByteArray();
    for (auto i = 0; i < IPV6_ADDR_LEN; i++)
    {
        ret_ip.addr.ipv6[i] = byte_addr[i];
    }
    return ret_ip;
}

std::string utils::net_specific::parse_ip_protocol(__u8 proto)
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

struct redirection_endpoint_mac utils::net_specific::get_redirection_endpoint(std::string ip, __u16 port)
{

    redirection_endpoint_mac end_pt{};
    std::memset(&end_pt, 0, sizeof(end_pt));
    get_interface_info(ip, end_pt);

    std::vector<int> values;
    if (ip.find(':') != std::string::npos)
    {
        std::istringstream iss(ip);
        std::string segment;
        while (std::getline(iss, segment, ':')) {
            values.push_back(std::stoi(segment));
        }

        end_pt.endpoint.ip.version = IPV6;
        for (int i=0; i<8; i++)
            end_pt.endpoint.ip.addr.ipv4[i] = values[i];
    }
    else
    {
        std::istringstream iss(ip);
        std::string segment;
        while (std::getline(iss, segment, '.')) {
            values.push_back(std::stoi(segment));
        }

        end_pt.endpoint.ip.version = IPV4;
        for (int i=0; i<4; i++)
            end_pt.endpoint.ip.addr.ipv4[i] = values[i]; //seg fault check
    }

    end_pt.endpoint.port = utils::common::get_correct_port(port);
    if (end_pt.endpoint.ip.version == IPV4)
    {
        for (int i = 0; i < 4; i++)
            std::cout << int(end_pt.endpoint.ip.addr.ipv4[i]) << ".";
    }
    else
    {
        for (int i = 0; i < 6; i++)
            std::cout << int(end_pt.endpoint.ip.addr.ipv6[i]) << ":";
    }
    return end_pt;
}