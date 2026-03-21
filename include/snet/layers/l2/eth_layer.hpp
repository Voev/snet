#pragma once
#include <snet/layers/layer.hpp>

namespace snet::layers
{

enum class EtherType : uint16_t
{
    IP = 0x0800,           ///< IP protocol version 4
    ARP = 0x0806,          ///< ARP
    ETHBRIDGE = 0x6558,    ///< Transparent Ethernet Bridging
    REVARP = 0x8035,       ///< Reverse ARP
    AT = 0x809B,           ///< AppleTalk protocol
    AARP = 0x80F3,         ///< AppleTalk ARP
    VLAN = 0x8100,         ///< IEEE 802.1Q VLAN tagging
    IPX = 0x8137,          ///< IPX
    IPV6 = 0x86dd,         ///< IP protocol version 6
    LOOPBACK = 0x9000,     ///< Loopback
    PPPOED = 0x8863,       ///< PPPoE discovery
    PPPOES = 0x8864,       ///< PPPoE session
    MPLS = 0x8847,         ///< MPLS
    PPP = 0x880B,          ///< Point-to-point protocol (PPP)
    ROCEV1 = 0x8915,       ///< RDMA over Converged Ethernet (RoCEv1)
    IEEE_802_1AD = 0x88A8, ///< IEEE 802.1ad Provider Bridge, Q-in-Q
    WAKE_ON_LAN = 0x0842,  ///< Wake on LAN
};

#pragma pack(push, 1)
/// @brief Ethernet II header
struct ether_header
{
    uint8_t dstMac[6];  ///< Destination MAC
    uint8_t srcMac[6];  ///< Source MAC
    uint16_t etherType; ///< EtherType
};
#pragma pack(pop)

} // namespace snet::layers
