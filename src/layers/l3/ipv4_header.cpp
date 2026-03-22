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
    if (!header_)
    {
        return UnknownProtocol;
    }

    return IPProtocolToProtocol(header_->protocol);
}

bool IPv4Header::initialize(const LayerInfo& layer, const Packet& packet) noexcept
{
    if (layer.protocol != g_ProtocolType)
    {
        return false;
    }

    if (layer.offset + sizeof(RawType) > packet.getDataLen())
    {
        return false;
    }

    header_ = reinterpret_cast<const RawType*>(packet.getData() + layer.offset);
    return true;
}

std::ostream& IPv4Header::print(std::ostream& os) const noexcept
{
    if (!header_)
    {
        os << "IPv4: [invalid]";
        return os;
    }

    os << "IPv4: " << srcAddr() << " -> " << dstAddr() << " (proto=" << static_cast<int>(protocol())
       << ", ttl=" << static_cast<int>(ttl()) << ", len=" << totalLen() << ")";

    return os;
}

} // namespace snet::layers