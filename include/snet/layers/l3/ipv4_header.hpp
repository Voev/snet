#pragma once

#include <cstdint>
#include <casket/utils/endianness.hpp>
#include <snet/layers/protocol.hpp>
#include <snet/layers/l3/ipv4_address.hpp>
#include <snet/layers/layer.hpp>

namespace snet::layers
{

/// @brief Raw IPv4 header structure as defined in RFC 791.
///
/// Represents the binary layout of an IPv4 header as it appears on the wire.
/// This structure is packed to ensure correct alignment and no padding.
#pragma pack(push, 1)
struct ipv4_header
{
#if (BYTE_ORDER == LITTLE_ENDIAN)
    uint8_t ihl : 4;     ///< Internet Header Length in 32-bit words.
    uint8_t version : 4; ///< IP version (should be 4 for IPv4).
#else
    uint8_t version : 4; ///< IP version (should be 4 for IPv4).
    uint8_t ihl : 4;     ///< Internet Header Length in 32-bit words.
#endif
    uint8_t tos;       ///< Type of Service field.
    uint16_t tot_len;  ///< Total packet length in bytes.
    uint16_t id;       ///< Identification field for fragmentation.
    uint16_t frag_off; ///< Fragment offset and flags.
    uint8_t ttl;       ///< Time To Live in hops.
    uint8_t protocol;  ///< Protocol number of encapsulated payload.
    uint16_t check;    ///< Header checksum.
    uint32_t saddr;    ///< Source IPv4 address.
    uint32_t daddr;    ///< Destination IPv4 address.
};
#pragma pack(pop)

class Packet;

/// @brief Represents an IPv4 header.
///
/// Provides access to IPv4 header fields including version, header length, TOS,
/// total length, identification, fragmentation flags, offset, TTL, protocol,
/// checksum, source/destination addresses, and optional options.
class IPv4Header
{
public:
    /// @brief Protocol type identifier for this header.
    static constexpr ProtocolType g_ProtocolType = IPv4;

    /// @brief Underlying raw header type.
    using RawType = ipv4_header;

    /// @brief IPv4 fragmentation flags.
    enum Flags : uint16_t
    {
        FLAG_RESERVED = 4, ///< Reserved flag (must be zero).
        DONT_FRAGMENT = 2, ///< Don't fragment flag.
        MORE_FRAGMENTS = 1 ///< More fragments flag.
    };

    /// @brief Default constructor.
    IPv4Header() = default;

    /// @brief Initializes the header with layer and packet data.
    /// @param [in] layer Layer information containing header location.
    /// @param [in] packet Reference to the packet containing the header.
    ///
    /// @return true if initialization succeeded, false otherwise.
    bool initialize(const LayerInfo& layer, const Packet& packet) noexcept;

    /// @brief Gets the next protocol type after IPv4.
    /// @return Protocol type of the encapsulated payload.
    ProtocolType getNextProtocol() const noexcept;

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

    /// @brief Gets the IP version (should be 4).
    /// @return IP version number.
    uint8_t version() const noexcept
    {
        return header_->version;
    }

    /// @brief Gets the header length in 32-bit words.
    /// @return Header length in 32-bit words (IHL field).
    uint8_t headerLen() const noexcept
    {
        return header_->ihl;
    }

    /// @brief Gets the header length in bytes.
    /// @return Header length in bytes.
    uint8_t headerLength() const noexcept
    {
        return header_->ihl * 4;
    }

    /// @brief Gets the Type of Service (ToS) field.
    /// @return ToS value.
    uint8_t tos() const noexcept
    {
        return header_->tos;
    }

    /// @brief Gets the total packet length in bytes.
    /// @return Total length including header and payload.
    uint16_t totalLen() const noexcept
    {
        return casket::be_to_host(header_->tot_len);
    }

    /// @brief Gets the identification field.
    /// @return Identification value used for reassembly.
    uint16_t id() const noexcept
    {
        return casket::be_to_host(header_->id);
    }

    /// @brief Gets the fragment offset in 8-byte units.
    /// @return Fragment offset value.
    uint16_t fragmentOffset() const noexcept
    {
        return casket::be_to_host(header_->frag_off) & 0x1FFF;
    }

    /// @brief Checks if more fragments follow.
    /// @return true if more fragments follow, false otherwise.
    bool isMoreFragments() const noexcept
    {
        return (casket::be_to_host(header_->frag_off) & 0x2000) != 0;
    }

    /// @brief Checks if the packet can be fragmented.
    /// @return true if fragmentation is disabled, false otherwise.
    bool dontFragment() const noexcept
    {
        return (casket::be_to_host(header_->frag_off) & 0x4000) != 0;
    }

    /// @brief Gets the fragmentation flags.
    /// @return Combination of fragmentation flags.
    Flags flags() const noexcept
    {
        return static_cast<Flags>(casket::be_to_host(header_->frag_off) >> 13);
    }

    /// @brief Gets the Time To Live (TTL) value.
    /// @return TTL value in hops.
    uint8_t ttl() const noexcept
    {
        return header_->ttl;
    }

    /// @brief Gets the protocol number of the encapsulated payload.
    /// @return IP protocol number (e.g., TCP=6, UDP=17).
    uint8_t protocol() const noexcept
    {
        return header_->protocol;
    }

    /// @brief Gets the header checksum.
    /// @return Checksum value in host byte order.
    uint16_t checksum() const noexcept
    {
        return casket::be_to_host(header_->check);
    }

    /// @brief Gets the source IPv4 address.
    /// @return Source IPv4 address.
    IPv4Address srcAddr() const noexcept
    {
        return IPv4Address(casket::be_to_host(header_->saddr));
    }

    /// @brief Gets the destination IPv4 address.
    /// @return Destination IPv4 address.
    IPv4Address dstAddr() const noexcept
    {
        return IPv4Address(casket::be_to_host(header_->daddr));
    }

    /// @brief Gets the options data if present.
    /// @return Pointer to options data, or nullptr if no options exist.
    const uint8_t* options() const noexcept
    {
        if (headerLen() > 5)
        {
            return reinterpret_cast<const uint8_t*>(header_) + sizeof(RawType);
        }
        return nullptr;
    }

    /// @brief Gets the length of options in bytes.
    /// @return Options length in bytes, or 0 if no options exist.
    size_t optionsLength() const noexcept
    {
        return headerLen() > 5 ? (headerLen() - 5) * 4 : 0;
    }

private:
    const RawType* header_ = nullptr; ///< Pointer to raw IPv4 header data.
};

} // namespace snet::layers