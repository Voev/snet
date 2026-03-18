#pragma once

#include <cstdint>
#include <casket/utils/endianness.hpp>
#include <snet/layers/protocol.hpp>
#include <snet/layers/l3/ipv4_address.hpp>
#include <snet/layers/layer.hpp>

namespace snet::layers
{

#pragma pack(push, 1)
struct ipv4_header
{
#if (BYTE_ORDER == LITTLE_ENDIAN)
    uint8_t ihl : 4;
    uint8_t version : 4;
#else
    uint8_t version : 4;
    uint8_t ihl : 4;
#endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};
#pragma pack(pop)

class Packet;

class IPv4Header
{
public:
    static constexpr ProtocolType protocol_type = IPv4;
    using raw_type = ipv4_header;

    enum Flags : uint16_t
    {
        FLAG_RESERVED = 4,
        DONT_FRAGMENT = 2,
        MORE_FRAGMENTS = 1
    };

    IPv4Header() = default;

    bool initialize(const LayerInfo& layer, const Packet& packet) noexcept;

    ProtocolType getNextProtocol() const noexcept;

    explicit operator bool() const noexcept
    {
        return m_Header != nullptr;
    }

    bool isValid() const noexcept
    {
        return m_Header != nullptr;
    }

    uint8_t version() const noexcept
    {
        return m_Header->version;
    }
    uint8_t headerLen() const noexcept
    {
        return m_Header->ihl;
    }
    uint8_t headerLength() const noexcept
    {
        return m_Header->ihl * 4;
    }
    uint8_t tos() const noexcept
    {
        return m_Header->tos;
    }

    uint16_t totalLen() const noexcept
    {
        return casket::be_to_host(m_Header->tot_len);
    }

    uint16_t id() const noexcept
    {
        return casket::be_to_host(m_Header->id);
    }

    uint16_t fragmentOffset() const noexcept
    {
        return casket::be_to_host(m_Header->frag_off) & 0x1FFF;
    }

    bool isMoreFragments() const noexcept
    {
        return (casket::be_to_host(m_Header->frag_off) & 0x2000) != 0;
    }

    bool dontFragment() const noexcept
    {
        return (casket::be_to_host(m_Header->frag_off) & 0x4000) != 0;
    }

    Flags flags() const noexcept
    {
        return static_cast<Flags>(casket::be_to_host(m_Header->frag_off) >> 13);
    }

    uint8_t ttl() const noexcept
    {
        return m_Header->ttl;
    }
    uint8_t protocol() const noexcept
    {
        return m_Header->protocol;
    }
    uint16_t checksum() const noexcept
    {
        return casket::be_to_host(m_Header->check);
    }

    IPv4Address srcAddr() const noexcept
    {
        return IPv4Address(casket::be_to_host(m_Header->saddr));
    }

    IPv4Address dstAddr() const noexcept
    {
        return IPv4Address(casket::be_to_host(m_Header->daddr));
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