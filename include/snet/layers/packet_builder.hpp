#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <casket/nonstd/span.hpp>
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
    /// @todo: refact this.
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
        ScalarBuffer<uint16_t> ipVec[1];
        ipVec[0].buffer = reinterpret_cast<uint16_t*>(ip);
        ipVec[0].len = ipSize; // 20
        ip->check =  casket::host_to_be(computeChecksum(ipVec, 1));

        IPAddress srcIP(IPv4Address(ip->saddr));
        IPAddress dstIP(IPv4Address(ip->daddr));
        tcp->check = 0;
        auto tcpCs = computePseudoHdrChecksum(reinterpret_cast<uint8_t*>(tcp),
                                              tcpLen,
                                              IPAddress::IPv4,
                                              6, // IPPROTO_TCP
                                              srcIP,
                                              dstIP);
        tcp->check = casket::host_to_be(tcpCs);
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