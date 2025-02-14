#define LOG_MODULE PacketLogModuleArpLayer

#include "ArpLayer.h"
#include "EthLayer.h"
#include "EndianPortable.h"

namespace pcpp
{

	ArpLayer::ArpLayer(ArpOpcode opCode, const MacAddress& senderMacAddr, const MacAddress& targetMacAddr,
	                   const IPv4Address& senderIpAddr, const IPv4Address& targetIpAddr)
	{
		const size_t headerLen = sizeof(arphdr);
		m_DataLen = headerLen;
		m_Data = new uint8_t[headerLen];
		memset(m_Data, 0, sizeof(headerLen));
		m_Protocol = ARP;

		arphdr* arpHeader = getArpHeader();
		arpHeader->opcode = htobe16(static_cast<uint16_t>(opCode));
		targetMacAddr.copyTo(arpHeader->targetMacAddr);
		senderMacAddr.copyTo(arpHeader->senderMacAddr);
		arpHeader->targetIpAddr = targetIpAddr.toInt();
		arpHeader->senderIpAddr = senderIpAddr.toInt();
	}

	void ArpLayer::computeCalculateFields()
	{
		arphdr* arpHeader = getArpHeader();
		arpHeader->hardwareType = htobe16(1);  // Ethernet
		arpHeader->hardwareSize = 6;
		arpHeader->protocolType = htobe16(PCPP_ETHERTYPE_IP);  // assume IPv4 over ARP
		arpHeader->protocolSize = 4;                           // assume IPv4 over ARP
		if (arpHeader->opcode == htobe16(ARP_REQUEST))
			MacAddress::Zero.copyTo(arpHeader->targetMacAddr);
	}

	bool ArpLayer::isRequest() const
	{
		return be16toh(getArpHeader()->opcode) == pcpp::ArpOpcode::ARP_REQUEST;
	}

	bool ArpLayer::isReply() const
	{
		return be16toh(getArpHeader()->opcode) == pcpp::ArpOpcode::ARP_REPLY;
	}

	std::string ArpLayer::toString() const
	{
		if (be16toh(getArpHeader()->opcode) == ARP_REQUEST)
		{
			return "ARP Layer, ARP request, who has " + getTargetIpAddr().toString() + " ? Tell " +
			       getSenderIpAddr().toString();
		}
		else
		{
			return "ARP Layer, ARP reply, " + getSenderIpAddr().toString() + " is at " +
			       getSenderMacAddress().toString();
		}
	}

	// Layer	|	Type	|	TargetIP	|	SenderIP	|	SenderMAC 
	std::string ArpLayer::toTSVString() const
	{
		if (be16toh(getArpHeader()->opcode) == ARP_REQUEST)
		{
			return "ARP Layer\tRequest\t" + getTargetIpAddr().toString() + "\t" + getSenderIpAddr().toString() + "\t-";
		}
		else
		{
			return "ARP Layer\tReply\t-\t" + getSenderIpAddr().toString() + "\t" + getSenderMacAddress().toString();
		}
	}
	std::string ArpLayer::toJSONString() const
	{
		if (be16toh(getArpHeader()->opcode) == ARP_REQUEST)
		{
			return "{\n\"Layer\": \"ARP Layer\",\n\"Type\": \"ARP request\",\n\"Target IP\": \"" + getTargetIpAddr().toString() + "\",\n\"Sender IP\": \"" +
			       getSenderIpAddr().toString() + "\"\n}";
		}
		else
		{
			return "{\n\"Layer\": \"ARP Layer\",\n\"Type\": \"ARP reply\",\n\"Sender IP\": \"" + getSenderIpAddr().toString() + "\",\n\"Sender MAC Address\": \"" +
			       getSenderMacAddress().toString() + "\"\n}";
		}
	}

}  // namespace pcpp
