#include <unordered_map>
#include <snet/layers/l2/eth_header.hpp>
#include <snet/layers/packet.hpp>

namespace snet::layers
{

static inline void PrintMac(std::ostream& os, nonstd::span<const uint8_t> mac)
{
    for (size_t i = 0; i < mac.size(); ++i)
    {
        if (i > 0)
        {
            os << ':';
        }
        os << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    }
    os << std::dec << std::setfill(' ');
};

static inline void PrintEtherType(std::ostream& os, const EtherType etherType) noexcept
{
    switch (etherType)
    {
    case EtherType::IP:
        os << "IPv4";
        break;
    case EtherType::ARP:
        os << "ARP";
        break;
    case EtherType::ETHBRIDGE:
        os << "Ethernet Bridging";
        break;
    case EtherType::REVARP:
        os << "Reverse ARP";
        break;
    case EtherType::AT:
        os << "AppleTalk";
        break;
    case EtherType::AARP:
        os << "AppleTalk ARP";
        break;
    case EtherType::VLAN:
        os << "VLAN (802.1Q)";
        break;
    case EtherType::IPX:
        os << "IPX";
        break;
    case EtherType::IPV6:
        os << "IPv6";
        break;
    case EtherType::LOOPBACK:
        os << "Loopback";
        break;
    case EtherType::PPPOED:
        os << "PPPoE Discovery";
        break;
    case EtherType::PPPOES:
        os << "PPPoE Session";
        break;
    case EtherType::MPLS:
        os << "MPLS";
        break;
    case EtherType::PPP:
        os << "PPP";
        break;
    case EtherType::ROCEV1:
        os << "RoCEv1";
        break;
    case EtherType::IEEE_802_1AD:
        os << "802.1ad (Q-in-Q)";
        break;
    case EtherType::WAKE_ON_LAN:
        os << "Wake-on-LAN";
        break;
    default:
        os << "Unknown";
        break;
    }
}

static inline ProtocolType EtherTypeToProtocol(EtherType etherType) noexcept
{
    static const std::unordered_map<EtherType, ProtocolType> g_EtherTypeMap = {
        {EtherType::IP, IPv4}, {EtherType::IPV6, IPv6}, {EtherType::ARP, ARP},
        /// @todo append extra porotocols
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
    if (!header_)
    {
        return UnknownProtocol;
    }

    return EtherTypeToProtocol(etherType());
}

bool EthernetHeader::initialize(const LayerInfo& layer, const Packet& packet) noexcept
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

std::ostream& EthernetHeader::print(std::ostream& os) const noexcept
{
    if (!header_)
    {
        os << "Ethernet Header: [invalid]";
        return os;
    }

    os << "Ethernet: ";
    PrintMac(os, srcMac());
    os << " -> ";
    PrintMac(os, dstMac());
    os << "  EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0') << header_->etherType << std::dec;
    os << " (";
    PrintEtherType(os, etherType());
    os << ")";

    return os;
}

} // namespace snet::layers