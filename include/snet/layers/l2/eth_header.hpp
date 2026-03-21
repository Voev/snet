#pragma once
#include <cstdint>
#include <iomanip>
#include <ostream>

#include <casket/nonstd/span.hpp>
#include <casket/utils/endianness.hpp>

#include <snet/layers/protocol.hpp>
#include <snet/layers/layer.hpp>

namespace snet::layers
{

#pragma pack(push, 1)

struct ethernet_header
{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t ether_type;
};

#pragma pack(pop)

class Packet;

class EthernetHeader
{
public:
    static constexpr ProtocolType protocol_type = Ethernet;
    using raw_type = ethernet_header;

    EthernetHeader() = default;

    ProtocolType getNextProtocol() const noexcept;

    bool initialize(const LayerInfo& layer, const Packet& packet) noexcept;

    explicit operator bool() const noexcept
    {
        return m_Header != nullptr;
    }
    bool isValid() const noexcept
    {
        return m_Header != nullptr;
    }

    const raw_type* operator->() const noexcept
    {
        return m_Header;
    }

    const raw_type& operator*() const noexcept
    {
        return *m_Header;
    }

    nonstd::span<const uint8_t> srcMac() const noexcept
    {
        return {m_Header->src_mac, 6};
    }

    nonstd::span<const uint8_t> dstMac() const noexcept
    {
        return {m_Header->dst_mac, 6};
    }

    uint16_t etherType() const noexcept
    {
        return casket::be_to_host(m_Header->ether_type);
    }

    bool isVlan() const noexcept
    {
        return etherType() == 0x8100;
    }

    bool isQinQ() const noexcept
    {
        return etherType() == 0x88A8;
    }

    std::ostream& print(std::ostream& os) const noexcept
    {
        if (!m_Header)
        {
            os << "Ethernet Header: [invalid]";
            return os;
        }

        auto printMac = [](std::ostream& os, nonstd::span<const uint8_t> mac) -> std::ostream&
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
            return os;
        };

        os << "Ethernet: ";
        printMac(os, srcMac());
        os << " -> ";
        printMac(os, dstMac());
        os << "  EtherType: 0x" << std::hex << std::setw(4) << std::setfill('0') << etherType() << std::dec;

        os << " (";
        switch (etherType())
        {
        case 0x0800:
            os << "IPv4";
            break;
        case 0x86DD:
            os << "IPv6";
            break;
        case 0x0806:
            os << "ARP";
            break;
        case 0x8035:
            os << "RARP";
            break;
        case 0x8100:
            os << "VLAN";
            break;
        case 0x88A8:
            os << "Q-in-Q";
            break;
        case 0x8847:
            os << "MPLS unicast";
            break;
        case 0x8848:
            os << "MPLS multicast";
            break;
        case 0x8863:
            os << "PPPoE Discovery";
            break;
        case 0x8864:
            os << "PPPoE Session";
            break;
        default:
            os << "unknown";
            break;
        }
        os << ")";

        return os;
    }

private:
    const raw_type* m_Header = nullptr;
};

} // namespace snet::layers

inline std::ostream& operator<<(std::ostream& os, const snet::layers::EthernetHeader& header)
{
    header.print(os);
    return os;
}