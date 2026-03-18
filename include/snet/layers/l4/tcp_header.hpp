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

class TCPHeader
{
public:
    static constexpr ProtocolType protocol_type = TCP;
    using raw_type = tcp_header;

    TCPHeader() = default;

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

    uint16_t srcPort() const noexcept
    {
        return casket::be_to_host(m_Header->source);
    }

    uint16_t dstPort() const noexcept
    {
        return casket::be_to_host(m_Header->dest);
    }

    uint32_t seqNum() const noexcept
    {
        return casket::be_to_host(m_Header->seq);
    }

    uint32_t ackNum() const noexcept
    {
        return casket::be_to_host(m_Header->ack_seq);
    }

    uint8_t headerLen() const noexcept
    {
        return m_Header->doff;
    }
    uint8_t headerLength() const noexcept
    {
        return m_Header->doff * 4;
    }

    bool isFIN() const noexcept
    {
        return m_Header->fin != 0;
    }
    bool isSYN() const noexcept
    {
        return m_Header->syn != 0;
    }
    bool isRST() const noexcept
    {
        return m_Header->rst != 0;
    }
    bool isPSH() const noexcept
    {
        return m_Header->psh != 0;
    }
    bool isACK() const noexcept
    {
        return m_Header->ack != 0;
    }
    bool isURG() const noexcept
    {
        return m_Header->urg != 0;
    }

    uint16_t window() const noexcept
    {
        return casket::be_to_host(m_Header->window);
    }

    uint16_t checksum() const noexcept
    {
        return casket::be_to_host(m_Header->check);
    }

    uint16_t urgentPtr() const noexcept
    {
        return casket::be_to_host(m_Header->urg_ptr);
    }

    const uint8_t* options() const noexcept
    {
        if (headerLen() > 5)
        {
            return reinterpret_cast<const uint8_t*>(m_Header) + sizeof(raw_type);
        }
        return nullptr;
    }

    size_t optionsLength() const noexcept
    {
        return headerLen() > 5 ? (headerLen() - 5) * 4 : 0;
    }

private:
    const raw_type* m_Header = nullptr;
};

} // namespace snet::layers