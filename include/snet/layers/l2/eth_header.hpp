#pragma once
#include <cstdint>

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

private:
    const raw_type* m_Header = nullptr;
};

} // namespace snet::layers