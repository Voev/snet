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
    void updateChecksums() noexcept
    {
        if (offset_ < sizeof(ipv4_header))
            return;

        auto* ip = reinterpret_cast<ipv4_header*>(buffer_);
        if (ip->version != 4 || ip->protocol != 6)
            return;

        const size_t ipSize = ip->ihl * 4;
        if (offset_ < ipSize + sizeof(tcp_header))
            return;

        auto* tcp = reinterpret_cast<tcp_header*>(buffer_ + ipSize);
        const size_t tcpLen = offset_ - ipSize;

        ip->check = 0;
        const ByteSpan ipSpan{reinterpret_cast<const uint8_t*>(ip), ipSize};
        ip->check = computeChecksum(ByteSpanVec{&ipSpan, 1});

        IPAddress srcIP(IPv4Address::fromNetwork(ip->saddr));
        IPAddress dstIP(IPv4Address::fromNetwork(ip->daddr));
        tcp->check = 0;
        const ByteSpan tcpSpan{reinterpret_cast<const uint8_t*>(tcp), tcpLen};
        tcp->check = computePseudoHdrChecksum(tcpSpan,
                                              4, // IPv4,
                                              6, // IPPROTO_TCP
                                              srcIP,
                                              dstIP);
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