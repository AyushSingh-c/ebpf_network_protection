#include "utils.h"

__u16 utils::common::get_correct_port(__u16 port)
{
    return ((port >> 8) & 0xff) + ((port & 0xff) << 8);
}

std::string utils::common::int_to_hex(int value) 
{
    std::ostringstream oss;
    oss << std::hex << value;
    std::string ret = oss.str();
    if (value < 16)
        ret = "0" + ret;
    return ret;
}

std::string utils::common::parse_ip(ip_address_t ip, __u16 port)
{
    if (ip.version == IPV4)
        return std::to_string(ip.addr.ipv4[0] & 0xff) + "." + std::to_string((ip.addr.ipv4[1]) & 0xff) + "." + std::to_string((ip.addr.ipv4[2]) & 0xff) + "." + std::to_string((ip.addr.ipv4[3]) & 0xff) + ":" + std::to_string(utils::common::get_correct_port(port));
    else
        return utils::common::int_to_hex(ip.addr.ipv6[0] & 0xffff) + "." + utils::common::int_to_hex((ip.addr.ipv6[1]) & 0xffff) + "." + utils::common::int_to_hex((ip.addr.ipv6[2]) & 0xffff) + "." + utils::common::int_to_hex((ip.addr.ipv6[3]) & 0xffff) + "." + utils::common::int_to_hex((ip.addr.ipv6[4]) & 0xffff) + "." + utils::common::int_to_hex((ip.addr.ipv6[5]) & 0xffff) + "." + utils::common::int_to_hex((ip.addr.ipv6[6]) & 0xffff) + "." + utils::common::int_to_hex((ip.addr.ipv6[7]) & 0xffff) + ":" + utils::common::int_to_hex(utils::common::get_correct_port(port));
}

ip_lpm_key utils::common::get_blocking_ip_key(std::string ip, uint8_t subnet)
{
    std::vector<int> values;
    std::istringstream iss(ip);
    std::string segment;

    while (std::getline(iss, segment, '.')) {
        values.push_back(std::stoi(segment));
    }

    ip_address_t rev_ip{};
    ip_lpm_key key{};
    std::memset(&rev_ip, 0, sizeof(ip_address_t));
    if (values.size() == 4)
    {
        rev_ip.version = IPV4;
        for (int i=0; i<4; i++)
            rev_ip.addr.ipv4[i] = values[i];
        key.prefix_len = 32 - subnet;
    }
    else if (values.size() == 8)
    {
        rev_ip.version = IPV6;
        for (int i=0; i<8; i++)
            rev_ip.addr.ipv6[i] = values[i];
        key.prefix_len = 128 - subnet;
    }

    key.addr = rev_ip;
    return key;
}

