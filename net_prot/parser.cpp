#include <string>
#include <iostream>
#include "parser.h"

bool Parser::is_ssh()
{
    return ssh_ingress_version_pkt && ssh_egress_version_pkt;
}

bool Parser::parse_for_ssh(pkt_parse_state& pkt_state)
{
    pkt_state.parse(2); //src port in ssh transport header
    pkt_state.parse(2); //dest port in ssh transport header
    pkt_state.parse(4); //seq in ssh transport header
    pkt_state.parse(4); //ack - seq in ssh transport header

    int data_off = (4 * (pkt_state.get_byte() >> 4)) - 12;  // we parsed 12 bytes already

    pkt_state.parse(data_off);

    if (pkt_state.check_bytes({0x53, 0x53, 0x48, 0x2d})) // for "SSH-"
    {
        if (pkt_state.ingress) 
            ssh_ingress_version_pkt = true;
        else
            ssh_egress_version_pkt = true;
    } 

    return is_ssh();
}

enum l7_proto Parser::parse(pkt_parse_state& pkt_state)
{
    if (parse_for_ssh(pkt_state))
        return l7_proto::ssh;
    return l7_proto::unknown;
}   