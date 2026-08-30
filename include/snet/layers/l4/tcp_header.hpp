#pragma once

#include <cassert>
#include <cstdint>
#include <ostream>
#include <casket/utils/endianness.hpp>

#include <snet/layers/protocol.hpp>
#include <snet/layers/layer.hpp>

namespace snet::layers
{

#pragma pack(push, 1)
struct tcp_header
{
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    union
    {
        struct
        {
#if (BYTE_ORDER == LITTLE_ENDIAN)
            uint16_t res1 : 4;
            uint16_t doff : 4;
            uint16_t fin : 1;
            uint16_t syn : 1;
            uint16_t rst : 1;
            uint16_t psh : 1;
            uint16_t ack : 1;
            uint16_t urg : 1;
            uint16_t res2 : 2;
#else
            uint16_t doff : 4;
            uint16_t res1 : 4;
            uint16_t res2 : 2;
            uint16_t urg : 1;
            uint16_t ack : 1;
            uint16_t psh : 1;
            uint16_t rst : 1;
            uint16_t syn : 1;
            uint16_t fin : 1;
#endif
        } bits;
        uint16_t flags;
    } u;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
#pragma pack(pop)

class TCPBits
{
public:
    explicit TCPBits(tcp_header* const header) noexcept
        : header_(header)
    {
        assert(header_ != nullptr && "TCPBits: header is nullptr");
    }

    TCPBits(const TCPBits&) = delete;
    TCPBits& operator=(const TCPBits&) = delete;

    TCPBits(TCPBits&&) noexcept = default;
    TCPBits& operator=(TCPBits&&) noexcept = default;

    /// @brief Set Data Offset field
    TCPBits& doff(uint8_t value) noexcept
    {
        if (header_ != nullptr) [[likely]]
        {
            header_->u.bits.doff = value;
        }
        return *this;
    }

    /// @brief Set RES1 field
    TCPBits& res1(uint8_t value) noexcept
    {
        if (header_ != nullptr) [[likely]]
        {
            header_->u.bits.res1 = value;
        }
        return *this;
    }

    /// @brief Set RES2 field
    TCPBits& res2(uint8_t value) noexcept
    {
        if (header_ != nullptr) [[likely]]
        {
            header_->u.bits.res2 = value;
        }
        return *this;
    }

    /// @brief Set FIN flag
    TCPBits& fin(bool set = true) noexcept
    {
        if (header_ != nullptr) [[likely]]
        {
            header_->u.bits.fin = set ? 1 : 0;
        }
        return *this;
    }

    /// @brief Set SYN flag
    TCPBits& syn(bool set = true) noexcept
    {
        if (header_ != nullptr) [[likely]]
        {
            header_->u.bits.syn = set ? 1 : 0;
        }
        return *this;
    }

    /// @brief Set RST flag
    TCPBits& rst(bool set = true) noexcept
    {
        if (header_ != nullptr) [[likely]]
        {
            header_->u.bits.rst = set ? 1 : 0;
        }
        return *this;
    }

    /// @brief Set PSH flag
    TCPBits& psh(bool set = true) noexcept
    {
        if (header_ != nullptr) [[likely]]
        {
            header_->u.bits.psh = set ? 1 : 0;
        }
        return *this;
    }

    /// @brief Set ACK flag
    TCPBits& ack(bool set = true) noexcept
    {
        if (header_ != nullptr) [[likely]]
        {
            header_->u.bits.ack = set ? 1 : 0;
        }
        return *this;
    }

    /// @brief Set URG flag
    TCPBits& urg(bool set = true) noexcept
    {
        if (header_ != nullptr) [[likely]]
        {
            header_->u.bits.urg = set ? 1 : 0;
        }
        return *this;
    }

    /// @brief Set all flags using bitmask (for use with tcp_flags constants)
    TCPBits& flags(uint16_t mask) noexcept
    {
        if (header_ != nullptr) [[likely]]
        {
            // Clear flags (bits 0-8), preserve DOFF and RES
            header_->u.flags = (header_->u.flags & ~0x01FF) | (mask & 0x01FF);
        }
        return *this;
    }

    /// @brief Set entire flags field directly
    TCPBits& raw(uint16_t value) noexcept
    {
        if (header_ != nullptr) [[likely]]
        {
            header_->u.flags = value;
        }
        return *this;
    }

    /// @brief Get raw pointer to TCP header
    [[nodiscard]] tcp_header* get() noexcept
    {
        return header_;
    }

    /// @brief Get const raw pointer to TCP header
    [[nodiscard]] const tcp_header* get() const noexcept
    {
        return header_;
    }

    /// @brief Check if the header is valid
    [[nodiscard]] bool isValid() const noexcept
    {
        return header_ != nullptr;
    }

private:
    tcp_header* const header_;
};

class Packet;

/// @brief Represents a TCP header.
/// 
/// Provides access to TCP header fields including source/destination ports,
/// sequence numbers, acknowledgment numbers, header length, flags, window size,
/// checksum, urgent pointer, and optional options.
class TCPHeader
{
public:
    /// @brief Protocol type identifier for this header.
    static constexpr ProtocolType g_ProtocolType = TCP;
    
    /// @brief Underlying raw header type.
    using RawType = tcp_header;

    /// @brief Default constructor.
    TCPHeader() = default;

    /// @brief Initializes the header with layer and packet data.
    /// @param [in] layer Layer information containing header location.
    /// @param [in] packet Reference to the packet containing the header.
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

    /// @brief Gets the source port number.
    /// @return Source port in host byte order.
    uint16_t srcPort() const noexcept
    {
        return casket::be_to_host(header_->source);
    }

    /// @brief Gets the destination port number.
    /// @return Destination port in host byte order.
    uint16_t dstPort() const noexcept
    {
        return casket::be_to_host(header_->dest);
    }

    /// @brief Gets the sequence number.
    /// @return Sequence number in host byte order.
    uint32_t seqNum() const noexcept
    {
        return casket::be_to_host(header_->seq);
    }

    /// @brief Gets the acknowledgment number.
    /// @return Acknowledgment number in host byte order.
    uint32_t ackNum() const noexcept
    {
        return casket::be_to_host(header_->ack_seq);
    }

    /// @brief Gets the header length in 32-bit words.
    /// @return Header length in 32-bit words (data offset field).
    uint8_t headerLen() const noexcept
    {
        return header_->u.bits.doff;
    }
    
    /// @brief Gets the header length in bytes.
    /// @return Header length in bytes.
    uint8_t headerLength() const noexcept
    {
        return header_->u.bits.doff * 4;
    }

    /// @brief Checks if the FIN flag is set.
    /// @return true if FIN flag is set, false otherwise.
    bool isFIN() const noexcept
    {
        return header_->u.bits.fin != 0;
    }
    
    /// @brief Checks if the SYN flag is set.
    /// @return true if SYN flag is set, false otherwise.
    bool isSYN() const noexcept
    {
        return header_->u.bits.syn != 0;
    }
    
    /// @brief Checks if the RST flag is set.
    /// @return true if RST flag is set, false otherwise.
    bool isRST() const noexcept
    {
        return header_->u.bits.rst != 0;
    }
    
    /// @brief Checks if the PSH flag is set.
    /// @return true if PSH flag is set, false otherwise.
    bool isPSH() const noexcept
    {
        return header_->u.bits.psh != 0;
    }
    
    /// @brief Checks if the ACK flag is set.
    /// @return true if ACK flag is set, false otherwise.
    bool isACK() const noexcept
    {
        return header_->u.bits.ack != 0;
    }
    
    /// @brief Checks if the URG flag is set.
    /// @return true if URG flag is set, false otherwise.
    bool isURG() const noexcept
    {
        return header_->u.bits.urg != 0;
    }

    /// @brief Gets the window size.
    /// @return Window size in host byte order.
    uint16_t window() const noexcept
    {
        return casket::be_to_host(header_->window);
    }

    /// @brief Gets the checksum.
    /// @return Checksum value in host byte order.
    uint16_t checksum() const noexcept
    {
        return casket::be_to_host(header_->check);
    }

    /// @brief Gets the urgent pointer.
    /// @return Urgent pointer in host byte order.
    uint16_t urgentPtr() const noexcept
    {
        return casket::be_to_host(header_->urg_ptr);
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

    
    /// @brief Returns a pointer to the raw TCP header.
    /// @return Pointer to raw TCP header data.
    const RawType* raw() const noexcept
    {
        return header_;
    }

    /// @brief Creates a TCPHeader from a raw TCP header pointer.
    /// @param [in] raw Pointer to raw TCP header.
    /// @return TCPHeader object.
    static TCPHeader fromRaw(const RawType* raw) noexcept
    {
        TCPHeader header;
        header.header_ = raw;
        return header;
    }

    /// @brief Gets the length of options in bytes.
    /// @return Options length in bytes, or 0 if no options exist.
    size_t optionsLength() const noexcept
    {
        return headerLen() > 5 ? (headerLen() - 5) * 4 : 0;
    }

    /// @brief Prints the TCP header to an output stream.
    /// @param [in,out] os Output stream to print to.
    ///
    /// @return Reference to the output stream for chaining.
    std::ostream& print(std::ostream& os) const noexcept;

private:
    const RawType* header_ = nullptr; ///< Pointer to raw TCP header data.
};

} // namespace snet::layers

inline std::ostream& operator<<(std::ostream& os, const snet::layers::TCPHeader& header)
{
    header.print(os);
    return os;
}