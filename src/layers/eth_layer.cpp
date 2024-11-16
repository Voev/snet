
#include <string.h>
#include <snet/layers/eth_layer.hpp>
#include <snet/layers/ipv4_layer.hpp>
#include <snet/layers/ipv6_layer.hpp>
#include <snet/layers/payload_layer.hpp>

namespace snet::layers
{


void EthLayer::parseNextLayer()
{
    if (m_DataLen <= sizeof(ether_header))
        return;

    ether_header* hdr = getEthHeader();
    uint8_t* payload = m_Data + sizeof(ether_header);
    size_t payloadLen = m_DataLen - sizeof(ether_header);

    switch (be16toh(hdr->etherType))
    {
    case PCPP_ETHERTYPE_IP:
        m_NextLayer =
            IPv4Layer::isDataValid(payload, payloadLen)
                ? static_cast<Layer*>(
                      new IPv4Layer(payload, payloadLen, this, m_Packet))
                : static_cast<Layer*>(
                      new PayloadLayer(payload, payloadLen, this, m_Packet));
        break;
    case PCPP_ETHERTYPE_IPV6:
        m_NextLayer =
            IPv6Layer::isDataValid(payload, payloadLen)
                ? static_cast<Layer*>(
                      new IPv6Layer(payload, payloadLen, this, m_Packet))
                : static_cast<Layer*>(
                      new PayloadLayer(payload, payloadLen, this, m_Packet));
        break;
    default:
        m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
    }
}

void EthLayer::computeCalculateFields()
{
    if (m_NextLayer == nullptr)
        return;

    switch (m_NextLayer->getProtocol())
    {
    case IPv4:
        getEthHeader()->etherType = htobe16(PCPP_ETHERTYPE_IP);
        break;
    case IPv6:
        getEthHeader()->etherType = htobe16(PCPP_ETHERTYPE_IPV6);
        break;
    case ARP:
        getEthHeader()->etherType = htobe16(PCPP_ETHERTYPE_ARP);
        break;
    case VLAN:
        getEthHeader()->etherType = htobe16(PCPP_ETHERTYPE_VLAN);
        break;
    default:
        return;
    }
}

std::string EthLayer::toString() const
{
    return "Ethernet II Layer";
            //, Src: " + getSourceMac().toString() +
            //", Dst: " + getDestMac().toString();
}

bool EthLayer::isDataValid(const uint8_t* data, size_t dataLen)
{
    if (dataLen >= sizeof(ether_header))
    {
        /**
         * Ethertypes: These are 16-bit identifiers appearing as the initial
         * two octets after the MAC destination and source (or after a
         * tag) which, when considered as an unsigned integer, are equal
         * to or larger than 0x0600.
         *
         * From: https://tools.ietf.org/html/rfc5342#section-2.3.2.1
         * More: IEEE Std 802.3 Clause 3.2.6
         */
        return be16toh(*(uint16_t*)(data + 12)) >= (uint16_t)0x0600;
    }
    else
    {
        return false;
    }
}

} // namespace pcpp
