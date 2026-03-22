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
struct ethernet_header
{
    uint8_t dstMac[6];  ///< Destination MAC
    uint8_t srcMac[6];  ///< Source MAC
    uint16_t etherType; ///< EtherType
};
#pragma pack(pop)

class Packet;

/// @brief Represents an Ethernet frame header.
///
/// Provides access to Ethernet header fields including source/destination MAC addresses
/// and EtherType. This class wraps a raw Ethernet header structure and provides
/// convenient accessors and validation.
class EthernetHeader
{
public:
    /// @brief Protocol type identifier for this header.
    static constexpr ProtocolType g_ProtocolType = Ethernet;

    /// @brief Underlying raw header type.
    using RawType = ethernet_header;

    /// @brief Default constructor.
    EthernetHeader() = default;

    /// @brief Gets the next protocol type after Ethernet.
    /// @return Protocol type of the encapsulated payload.
    ProtocolType getNextProtocol() const noexcept;

    /// @brief Initializes the header with layer and packet data.
    /// @param[in] layer Layer information containing header location.
    /// @param[in] packet Reference to the packet containing the header.
    ///
    /// @return true if initialization succeeded, false otherwise.
    bool initialize(const LayerInfo& layer, const Packet& packet) noexcept;

    /// @brief Checks if the header is valid (non-null).
    /// @return true if header points to valid data, false otherwise.
    explicit operator bool() const noexcept
    {
        return header_ != nullptr;
    }

    /// @brief Checks if the header is valid (non-null).
    /// @return true if header points to valid data, false otherwise.
    bool isValid() const noexcept
    {
        return header_ != nullptr;
    }

    /// @brief Accesses the raw header structure via arrow operator.
    /// @return Pointer to the raw Ethernet header.
    const RawType* operator->() const noexcept
    {
        return header_;
    }

    /// @brief Dereferences to the raw header structure.
    /// @return Reference to the raw Ethernet header.
    const RawType& operator*() const noexcept
    {
        return *header_;
    }

    /// @brief Gets the source MAC address.
    /// @return Span of 6 bytes containing the source MAC address.
    nonstd::span<const uint8_t> srcMac() const noexcept
    {
        return {header_->srcMac, 6};
    }

    /// @brief Gets the destination MAC address.
    /// @return Span of 6 bytes containing the destination MAC address.
    nonstd::span<const uint8_t> dstMac() const noexcept
    {
        return {header_->dstMac, 6};
    }

    /// @brief Gets the EtherType field in host byte order.
    /// @return EtherType value indicating the payload protocol.
    EtherType etherType() const noexcept
    {
        return static_cast<EtherType>(casket::be_to_host(header_->etherType));
    }

    /// @brief Prints the Ethernet header to an output stream.
    /// @param [in,out] os Output stream to print to.
    ///
    /// @return Reference to the output stream for chaining.
    std::ostream& print(std::ostream& os) const noexcept;

private:
    const RawType* header_ = nullptr; ///< Pointer to raw Ethernet header data.
};

} // namespace snet::layers

inline std::ostream& operator<<(std::ostream& os, const snet::layers::EthernetHeader& header)
{
    header.print(os);
    return os;
}
