#pragma once

#include <cstdint>
#include <iomanip>
#include <ostream>
#include <string>

#include <casket/nonstd/span.hpp>
#include <casket/utils/endianness.hpp>

#include <snet/layers/protocol.hpp>
#include <snet/layers/layer.hpp>

namespace snet::layers
{

/// @brief ARP operation codes (RFC 826 and extensions).
enum class ArpOp : uint16_t
{
    Request = 1,      ///< ARP Request
    Reply = 2,        ///< ARP Reply
    RarpRequest = 3,  ///< Reverse ARP Request
    RarpReply = 4,    ///< Reverse ARP Reply
    DrarpRequest = 5, ///< Dynamic RARP Request
    DrarpReply = 6,   ///< Dynamic RARP Reply
    DrarpError = 7,   ///< Dynamic RARP Error
    InarpRequest = 8, ///< InARP Request
    InarpReply = 9,   ///< InARP Reply
    ArpNak = 10,      ///< ARP NAK
};

#pragma pack(push, 1)
/// @brief ARP header (for IPv4 over Ethernet).
struct arp_header
{
    uint16_t htype; ///< Hardware type (1 = Ethernet)
    uint16_t ptype; ///< Protocol type (0x0800 = IPv4)
    uint8_t hlen;   ///< Hardware address length (6)
    uint8_t plen;   ///< Protocol address length (4)
    uint16_t op;    ///< Operation code
    uint8_t sha[6]; ///< Sender hardware address
    uint32_t spa;   ///< Sender protocol address
    uint8_t tha[6]; ///< Target hardware address
    uint32_t tpa;   ///< Target protocol address
};
#pragma pack(pop)

class Packet;

/// @brief Represents an ARP header.
///
/// Provides access to ARP header fields including hardware/protocol types,
/// operation code, sender and target addresses. Wraps a raw ARP header
/// structure and provides convenient accessors and validation.
///
/// @note This header is valid for the common case of IPv4-over-Ethernet ARP.
///       For non-standard hardware/protocol types, use the raw struct directly.
class ArpHeader
{
public:
    /// @brief Protocol type identifier for this header.
    static constexpr ProtocolType g_ProtocolType = ARP;

    /// @brief Underlying raw header type.
    using RawType = arp_header;

    /// @brief Default constructor.
    ArpHeader() = default;

    /// @brief Gets the next protocol type after ARP (always Unknown).
    /// @return UnknownProtocol — ARP carries no encapsulated protocol.
    ProtocolType getNextProtocol() const noexcept
    {
        return UnknownProtocol;
    }

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
    /// @return Pointer to the raw ARP header.
    const RawType* operator->() const noexcept
    {
        return header_;
    }

    /// @brief Dereferences to the raw header structure.
    /// @return Reference to the raw ARP header.
    const RawType& operator*() const noexcept
    {
        return *header_;
    }

    /// @brief Gets the hardware type in host byte order.
    /// @return Hardware type (1 = Ethernet).
    uint16_t hardwareType() const noexcept
    {
        return casket::be_to_host(header_->htype);
    }

    /// @brief Gets the protocol type in host byte order.
    /// @return Protocol type (0x0800 = IPv4).
    uint16_t protocolType() const noexcept
    {
        return casket::be_to_host(header_->ptype);
    }

    /// @brief Gets the hardware address length.
    /// @return Length of hardware addresses in bytes (6 for Ethernet).
    uint8_t hardwareLen() const noexcept
    {
        return header_->hlen;
    }

    /// @brief Gets the protocol address length.
    /// @return Length of protocol addresses in bytes (4 for IPv4).
    uint8_t protocolLen() const noexcept
    {
        return header_->plen;
    }

    /// @brief Gets the operation code.
    /// @return ARP operation code (Request/Reply/...).
    ArpOp operation() const noexcept
    {
        return static_cast<ArpOp>(casket::be_to_host(header_->op));
    }

    /// @brief Gets the sender hardware address.
    /// @return Span of hlen bytes containing the sender MAC.
    nonstd::span<const uint8_t> senderHwAddr() const noexcept
    {
        return {header_->sha, header_->hlen};
    }

    /// @brief Gets the sender protocol address (raw, network byte order).
    /// @return 32-bit sender protocol address.
    uint32_t senderProtoAddr() const noexcept
    {
        return header_->spa;
    }

    /// @brief Gets the target hardware address.
    /// @return Span of hlen bytes containing the target MAC.
    nonstd::span<const uint8_t> targetHwAddr() const noexcept
    {
        return {header_->tha, header_->hlen};
    }

    /// @brief Gets the target protocol address (raw, network byte order).
    /// @return 32-bit target protocol address.
    uint32_t targetProtoAddr() const noexcept
    {
        return header_->tpa;
    }

    /// @brief Prints the ARP header to an output stream.
    /// @param [in,out] os Output stream to print to.
    ///
    /// @return Reference to the output stream for chaining.
    std::ostream& print(std::ostream& os) const noexcept;

private:
    const RawType* header_ = nullptr; ///< Pointer to raw ARP header data.
};

} // namespace snet::layers

inline std::ostream& operator<<(std::ostream& os, const snet::layers::ArpHeader& header)
{
    header.print(os);
    return os;
}