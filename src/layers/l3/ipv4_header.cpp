#include <snet/layers/l3/ipv4_header.hpp>
#include <snet/layers/packet.hpp>

namespace snet::layers
{

inline ProtocolType IPProtocolToProtocol(uint8_t ipProtocol) noexcept
{
    static const std::unordered_map<uint8_t, ProtocolType> protocolMap = {
        {static_cast<uint8_t>(IPProto::Code::TCP), TCP},
        {static_cast<uint8_t>(IPProto::Code::UDP), UDP},
    };

    auto it = protocolMap.find(ipProtocol);
    if (it != protocolMap.end())
    {
        return it->second;
    }

    return UnknownProtocol;
}

ProtocolType IPv4Header::getNextProtocol() const noexcept
{
    if (!m_Header)
    {
        return UnknownProtocol;
    }

    return IPProtocolToProtocol(m_Header->protocol);
}

bool IPv4Header::initialize(const LayerInfo& layer, const Packet& packet) noexcept
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