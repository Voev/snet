#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <casket/nonstd/span.hpp>
#include <snet/layers/header_builder.hpp>

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

    PacketType* build() noexcept
    {
        if (!pkt_ || offset_ == 0)
        {
            return nullptr;
        }

        updateChecksums();
        updatePacketView();

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
        if (offset_ < sizeof(ethernet_header) + sizeof(ipv4_header))
            return;

        auto* ip = tryGetIp();
        if (ip && ip->protocol == 6)
        {
            auto* tcp = tryGetTcp(ip);
            if (tcp)
            {
                size_t ip_len = offset_ - sizeof(ethernet_header);
                ip->tot_len = htobe16(ip_len);
                ip->check = 0;
                ip->check = ipChecksum(ip);

                tcp->check = 0;
                tcp->check = tcpChecksum(ip, tcp);
            }
        }
    }

    void updatePacketView() noexcept
    {
        pkt_->asPacket()->setRawData(nonstd::span<const uint8_t>(buffer_, offset_), LINKTYPE_ETHERNET);
    }

    ipv4_header* tryGetIp() noexcept
    {
        if (offset_ < sizeof(ethernet_header) + sizeof(ipv4_header))
        {
            return nullptr;
        }

        auto* ip = reinterpret_cast<ipv4_header*>(buffer_ + sizeof(ethernet_header));
        return (ip->version == 4) ? ip : nullptr;
    }

    tcp_header* tryGetTcp(const ipv4_header* ip) noexcept
    {
        size_t ip_size = ip->ihl * 4;
        if (offset_ < sizeof(ethernet_header) + ip_size + sizeof(tcp_header))
        {
            return nullptr;
        }

        return reinterpret_cast<tcp_header*>(buffer_ + sizeof(ethernet_header) + ip_size);
    }

    static uint16_t ipChecksum(const ipv4_header* ip) noexcept
    {
        uint32_t sum = 0;
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(ip);
        size_t words = ip->ihl * 2;

        for (size_t i = 0; i < words; ++i)
        {
            sum += be16toh(ptr[i]);
            if (sum & 0x80000000)
                sum = (sum & 0xFFFF) + (sum >> 16);
        }

        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return htobe16(~sum & 0xFFFF);
    }

    static uint16_t tcpChecksum(const ipv4_header* ip, const tcp_header* tcp) noexcept
    {
        struct Pseudo
        {
            uint32_t src, dst;
            uint8_t zero, proto;
            uint16_t len;
        };

        size_t ip_size = ip->ihl * 4;
        size_t tcp_len = tcp->doff * 4;

        Pseudo pseudo;
        pseudo.src = ip->saddr;
        pseudo.dst = ip->daddr;
        pseudo.zero = 0;
        pseudo.proto = 6;
        pseudo.len = htobe16(tcp_len);

        uint32_t sum = 0;
        const uint16_t* ptr = reinterpret_cast<const uint16_t*>(&pseudo);
        for (size_t i = 0; i < sizeof(Pseudo) / 2; ++i)
        {
            sum += be16toh(ptr[i]);
            if (sum & 0x80000000)
                sum = (sum & 0xFFFF) + (sum >> 16);
        }

        const uint16_t* tcpPtr = reinterpret_cast<const uint16_t*>(tcp);
        size_t words = (tcp_len + 1) / 2;
        for (size_t i = 0; i < words; ++i)
        {
            uint16_t val = (i * 2 + 1 < tcp_len) ? be16toh(tcpPtr[i]) : 0;
            sum += val;
            if (sum & 0x80000000)
                sum = (sum & 0xFFFF) + (sum >> 16);
        }

        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return htobe16(~sum & 0xFFFF);
    }

    PacketType* pkt_;
    uint8_t* buffer_;
    size_t capacity_;
    size_t offset_;
    bool built_;
};

} // namespace snet::layers