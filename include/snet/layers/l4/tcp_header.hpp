#pragma once

#include <cstdint>
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
#if (BYTE_ORDER == LITTLE_ENDIAN)
    uint16_t res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, res2 : 2;
#else
    uint16_t doff : 4, res1 : 4, res2 : 2, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;
#endif
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
#pragma pack(pop)

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
        return header_->doff;
    }
    
    /// @brief Gets the header length in bytes.
    /// @return Header length in bytes.
    uint8_t headerLength() const noexcept
    {
        return header_->doff * 4;
    }

    /// @brief Checks if the FIN flag is set.
    /// @return true if FIN flag is set, false otherwise.
    bool isFIN() const noexcept
    {
        return header_->fin != 0;
    }
    
    /// @brief Checks if the SYN flag is set.
    /// @return true if SYN flag is set, false otherwise.
    bool isSYN() const noexcept
    {
        return header_->syn != 0;
    }
    
    /// @brief Checks if the RST flag is set.
    /// @return true if RST flag is set, false otherwise.
    bool isRST() const noexcept
    {
        return header_->rst != 0;
    }
    
    /// @brief Checks if the PSH flag is set.
    /// @return true if PSH flag is set, false otherwise.
    bool isPSH() const noexcept
    {
        return header_->psh != 0;
    }
    
    /// @brief Checks if the ACK flag is set.
    /// @return true if ACK flag is set, false otherwise.
    bool isACK() const noexcept
    {
        return header_->ack != 0;
    }
    
    /// @brief Checks if the URG flag is set.
    /// @return true if URG flag is set, false otherwise.
    bool isURG() const noexcept
    {
        return header_->urg != 0;
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

    /// @brief Gets the length of options in bytes.
    /// @return Options length in bytes, or 0 if no options exist.
    size_t optionsLength() const noexcept
    {
        return headerLen() > 5 ? (headerLen() - 5) * 4 : 0;
    }

private:
    const RawType* header_ = nullptr; ///< Pointer to raw TCP header data.
};

} // namespace snet::layers