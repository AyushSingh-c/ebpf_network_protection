#include <vector>

enum class l7_proto : int8_t
{
    ssh = 1,
    unknown = 127
};

struct pkt_parse_state
{
    std::vector<unsigned char> pkt_data;
    bool ingress;
    int index = 0;

    void parse(int bytes)
    {
        index = (index+bytes) >= pkt_data.size() ? pkt_data.size() : (index+bytes);
    }

    unsigned char get_byte()
    {
        if (index < pkt_data.size())
            return pkt_data[index];
        return 0;
    }

    bool check_byte(unsigned char byte)
    {
        if (index < pkt_data.size())
            return byte == pkt_data[index];
        return false;
    }

    bool check_bytes(const std::vector<unsigned char>& bytes)
    {
        if (index == pkt_data.size())
            return false;
        
        for (int i=index, j=0; i<pkt_data.size() && j<bytes.size() ; i++, j++)
        {
            if (pkt_data[i] != bytes[j])
                return false;
        }
        return true;
    }
};

class Parser
{
public:
    enum l7_proto parse(pkt_parse_state& pkt_state);
private:
    bool ssh_ingress_version_pkt = false;
    bool ssh_egress_version_pkt = false;
    bool is_ssh(); 
    bool parse_for_ssh(pkt_parse_state& pkt_state);
};