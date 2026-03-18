#include <unordered_map>
#include <snet/layers/l2/eth_header.hpp>
#include <snet/layers/l2/eth_layer.hpp>

#include <snet/layers/packet.hpp>

namespace snet::layers
{

static inline ProtocolType EtherTypeToProtocol(uint16_t etherType) noexcept
{
    static const std::unordered_map<uint16_t, ProtocolType> g_EtherTypeMap = {
        {static_cast<uint16_t>(EtherType::IP), IPv4},
        {static_cast<uint16_t>(EtherType::IPV6), IPv6},
        {static_cast<uint16_t>(EtherType::ARP), ARP},
    };

    auto it = g_EtherTypeMap.find(etherType);
    if (it != g_EtherTypeMap.end())
    {
        return it->second;
    }

    return UnknownProtocol;
}

ProtocolType EthernetHeader::getNextProtocol() const noexcept
{
    if (!m_Header)
    {
        return UnknownProtocol;
    }

    return EtherTypeToProtocol(etherType());
}

bool EthernetHeader::initialize(const LayerInfo& layer, const Packet& packet) noexcept
{
    if (layer.protocol != protocol_type)
    {
        return false;
    }

    if (layer.offset + sizeof(raw_type) > packet.getDataLen())
    {
        return false;
    }

    m_Header = reinterpret_cast<const raw_type*>(packet.getData() + layer.offset);
    return true;
}

} // namespace snet::layers