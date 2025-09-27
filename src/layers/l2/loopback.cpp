#include <string.h>
#include <snet/layers/l2/eth_layer.hpp>
#include <snet/layers/l2/loopback.hpp>
#include <snet/layers/l3/ipv4_layer.hpp>
#include <snet/layers/l3/ipv6_layer.hpp>
#include <snet/layers/payload_layer.hpp>

#include <casket/utils/byteswap.hpp>

#define IEEE_802_3_MAX_LEN 0x5dc

namespace snet::layers
{

NullLoopbackLayer::NullLoopbackLayer(uint32_t family)
{
    const size_t dataLen = sizeof(uint32_t);
    m_DataLen = dataLen;
    m_Data = new uint8_t[dataLen];
    memset(m_Data, 0, dataLen);
    m_Protocol = NULL_LOOPBACK;

    setFamily(family);
}

uint32_t NullLoopbackLayer::getFamily() const
{
    uint32_t family = *(uint32_t*)m_Data;
    if ((family & 0xFFFF0000) != 0)
    {
        if ((family & 0xFF000000) == 0 && (family & 0x00FF0000) < 0x00060000)
        {
            family >>= 16;
        }
        else
        {
            family = bswap_32(family);
        }
    }
    else if ((family & 0x000000FF) == 0 && (family & 0x0000FF00) < 0x00000600)
    {
        family = bswap_16(family & 0xFFFF);
    }

    return family;
}

void NullLoopbackLayer::setFamily(uint32_t family)
{
    *m_Data = family;
}

void NullLoopbackLayer::parseNextLayer()
{
    uint8_t* payload = m_Data + sizeof(uint32_t);
    size_t payloadLen = m_DataLen - sizeof(uint32_t);

    uint32_t family = getFamily();
    if (family > IEEE_802_3_MAX_LEN)
    {
        auto ethType = static_cast<EtherType>(family);
        switch (ethType)
        {
        case EtherType::IP:
            m_NextLayer =
                IPv4Layer::isDataValid(payload, payloadLen)
                    ? static_cast<Layer*>(
                          new IPv4Layer(payload, payloadLen, this, m_Packet))
                    : static_cast<Layer*>(new PayloadLayer(payload, payloadLen,
                                                           this, m_Packet));
            return;
        case EtherType::IPV6:
            m_NextLayer =
                IPv6Layer::isDataValid(payload, payloadLen)
                    ? static_cast<Layer*>(
                          new IPv6Layer(payload, payloadLen, this, m_Packet))
                    : static_cast<Layer*>(new PayloadLayer(payload, payloadLen,
                                                           this, m_Packet));
            return;
        default:
            m_NextLayer = new PayloadLayer(payload, payloadLen, this, m_Packet);
            return;
        }
    }

    switch (family)
    {
    case SNET_BSD_AF_INET:
        m_NextLayer =
            IPv4Layer::isDataValid(payload, payloadLen)
                ? static_cast<Layer*>(
                      new IPv4Layer(payload, payloadLen, this, m_Packet))
                : static_cast<Layer*>(
                      new PayloadLayer(payload, payloadLen, this, m_Packet));
        break;
    case SNET_BSD_AF_INET6_BSD:
    case SNET_BSD_AF_INET6_FREEBSD:
    case SNET_BSD_AF_INET6_DARWIN:
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

std::string NullLoopbackLayer::toString() const
{
    return "Null/Loopback";
}

} // namespace snet::layers
