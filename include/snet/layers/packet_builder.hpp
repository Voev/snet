#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

#include <casket/nonstd/span.hpp>
#include <casket/utils/load_store.hpp>

#include <snet/layers/header_builder.hpp>
#include <snet/layers/checksums.hpp>

namespace snet::layers
{

template <typename PacketType>
class PacketBuilder
{
public:
    explicit PacketBuilder(PacketType* packet) noexcept
        : pkt_(packet)
        , buffer_(packet ? packet->getData() : nullptr)
        , capacity_(packet ? packet->getCapacity() : 0)
        , offset_(0)
        , built_(false)
    {
        if (pkt_)
            pkt_->reset();
    }

    template <typename HeaderType>
    HeaderBuilder<HeaderType> layer() noexcept
    {
        return HeaderBuilder<HeaderType>(buffer_ + offset_,
                                         capacity_ - offset_,
                                         [this](size_t bytes)
                                         {
                                             offset_ += bytes;
                                         });
    }

    HeaderBuilder<ethernet_header> eth() noexcept
    {
        return layer<ethernet_header>();
    }

    HeaderBuilder<ipv4_header> ipv4() noexcept
    {
        return layer<ipv4_header>();
    }

    HeaderBuilder<tcp_header> tcp() noexcept
    {
        return layer<tcp_header>();
    }

    PacketBuilder& payload(const void* data, size_t len) noexcept
    {
        if (buffer_ && offset_ + len <= capacity_ && len > 0)
        {
            std::memcpy(buffer_ + offset_, data, len);
            offset_ += len;
        }
        return *this;
    }

    PacketBuilder& payload(const std::string& data) noexcept
    {
        return payload(data.data(), data.size());
    }

    PacketType* build(LinkLayerType linkType = LINKTYPE_ETHERNET) noexcept
    {
        if (!pkt_ || offset_ == 0)
        {
            return nullptr;
        }

        updateChecksums();
        updatePacketView(linkType);

        built_ = true;
        return pkt_;
    }

    size_t offset() const noexcept
    {
        return offset_;
    }

    size_t remaining() const noexcept
    {
        return capacity_ - offset_;
    }

    uint8_t* buffer() const noexcept
    {
        return buffer_;
    }

    PacketType* packet() const noexcept
    {
        return pkt_;
    }

    bool isBuilt() const noexcept
    {
        return built_;
    }

private:
private:
    /// Recompute IPv4 header checksum (if applicable) and transport-layer
    /// (TCP/UDP) checksum for IPv4 or IPv6 packets.
    void updateChecksums() noexcept
    {
        if (offset_ < 1)
            return;

        const uint8_t version = buffer_[0] >> 4;

        if (version == 4)
            updateChecksumsIpv4();
        else if (version == 6)
            updateChecksumsIpv6();
    }

    /// IPv4: header checksum + TCP/UDP checksum via pseudo header.
    void updateChecksumsIpv4() noexcept
    {
        if (offset_ < sizeof(ipv4_header))
            return;

        auto* ip = reinterpret_cast<ipv4_header*>(buffer_);
        if (ip->version != 4)
            return;

        const size_t ipSize = static_cast<size_t>(ip->ihl) * 4;
        if (ipSize < sizeof(ipv4_header) || offset_ < ipSize)
            return;

        // IPv4 header checksum
        constexpr size_t kIpCheckOff = offsetof(ipv4_header, check);

        casket::store_be<uint16_t>(0, buffer_ + kIpCheckOff);

        const ByteSpan ipSpan{buffer_, ipSize};
        const uint16_t ipCheck = computeChecksum(ByteSpanVec{&ipSpan, 1});

        casket::store_be<uint16_t>(ipCheck, buffer_ + kIpCheckOff);

        // Transport checksum
        const uint8_t protocol = ip->protocol;
        if (protocol != 6 && protocol != 17) // TCP / UDP
            return;

        const size_t l4Offset = ipSize;
        if (offset_ < l4Offset + 8)
            return;

        const size_t l4Len = offset_ - l4Offset;
        const size_t l4CheckOff = (protocol == 6) ? 16 : 6;

        casket::store_be<uint16_t>(0, buffer_ + l4Offset + l4CheckOff);

        const ByteSpan l4Span{buffer_ + l4Offset, l4Len};

        const IPAddress srcIP(IPv4Address(ip->saddr));
        const IPAddress dstIP(IPv4Address(ip->daddr));

        uint16_t l4Check = computePseudoHdrChecksum(l4Span, 4, protocol, srcIP, dstIP);

        // RFC 768: UDP checksum of zero is transmitted as 0xFFFF.
        if (protocol == 17 && l4Check == 0)
            l4Check = 0xFFFF;

        casket::store_be<uint16_t>(l4Check, buffer_ + l4Offset + l4CheckOff);
    }

    /// IPv6: no header checksum; only TCP/UDP checksum via pseudo header.
    ///
    /// Extension headers are not supported: if the next-header field does not
    /// directly point to TCP/UDP, the transport checksum is left untouched.
    void updateChecksumsIpv6() noexcept
    {
        constexpr size_t kIpv6HeaderSize = 40;
        if (offset_ < kIpv6HeaderSize)
            return;

        const uint8_t* ip6 = buffer_;

        if ((ip6[0] >> 4) != 6)
            return;

        const uint8_t protocol = ip6[6]; // next_header
        if (protocol != 6 && protocol != 17)
            return;

        const size_t l4Offset = kIpv6HeaderSize;
        if (offset_ < l4Offset + 8)
            return;

        const size_t l4Len = offset_ - l4Offset;
        const size_t l4CheckOff = (protocol == 6) ? 16 : 6;

        casket::store_be<uint16_t>(0, buffer_ + l4Offset + l4CheckOff);

        const ByteSpan l4Span{buffer_ + l4Offset, l4Len};

        // Source / destination IPv6 addresses are the 16 bytes at offsets
        // 8..23 and 24..39 of the IPv6 header.
        const IPAddress srcIP = IPAddress::fromRaw(ip6 + 8, 16);
        const IPAddress dstIP = IPAddress::fromRaw(ip6 + 24, 16);

        uint16_t l4Check = computePseudoHdrChecksum(l4Span, 6, protocol, srcIP, dstIP);

        // RFC 8200 §8.1: UDP checksum of zero is transmitted as 0xFFFF.
        if (protocol == 17 && l4Check == 0)
            l4Check = 0xFFFF;

        casket::store_be<uint16_t>(l4Check, buffer_ + l4Offset + l4CheckOff);
    }

    inline void updatePacketView(LinkLayerType linkType) noexcept
    {
        pkt_->asPacket()->setRawData(nonstd::span<const uint8_t>(buffer_, offset_), linkType);
    }

    PacketType* pkt_;
    uint8_t* buffer_;
    size_t capacity_;
    size_t offset_;
    bool built_;
};

} // namespace snet::layers