#pragma once
#include <cstdint>
#include <cstring>
#include <memory>
#include <casket/nonstd/span.hpp>
#include <casket/utils/container_of.hpp>
#include <snet/layers/packet.hpp>
#include <snet/layers/timestamp.hpp>

namespace snet::layers
{

class InMemoryPacket final
{
public:
    explicit InMemoryPacket(size_t maxPacketSize, size_t headroom = 0)
        : headroom_(headroom)
    {
        assert(headroom <= maxPacketSize);
        allocate(maxPacketSize);
    }

    ~InMemoryPacket() noexcept = default;

    InMemoryPacket(const InMemoryPacket&) = delete;
    InMemoryPacket& operator=(const InMemoryPacket&) = delete;

    InMemoryPacket(InMemoryPacket&& other) noexcept
        : packet_(std::move(other.packet_))
        , buffer_(std::move(other.buffer_))
        , capacity_(other.capacity_)
        , headroom_(other.headroom_)
        , data_(other.data_)
    {
        other.packet_.clear();
        other.data_ = nullptr;
        other.capacity_ = 0;
        other.headroom_ = 0;
    }

    InMemoryPacket& operator=(InMemoryPacket&& other) noexcept
    {
        if (this != &other)
        {
            packet_ = std::move(other.packet_);
            buffer_ = std::move(other.buffer_);
            capacity_ = other.capacity_;
            headroom_ = other.headroom_;
            data_ = other.data_;

            other.packet_.clear();
            other.data_ = nullptr;
            other.capacity_ = 0;
            other.headroom_ = 0;
        }
        return *this;
    }

    void allocate(size_t size)
    {
        if (size > capacity_)
        {
            buffer_ = std::make_unique<uint8_t[]>(size);
            data_ = buffer_.get();
            capacity_ = size;
            packet_.clear();
        }
    }

    void reset() noexcept
    {
        packet_.clear();
        // data_ remains allocated
    }

    void setData(const uint8_t* data, size_t len, LinkLayerType linkType = LINKTYPE_ETHERNET)
    {
        if (!data || len == 0 || len > getCapacity())
            return;

        uint8_t* dst = getData();
        std::memcpy(dst, data, len);
        packet_.setRawData(nonstd::span<const uint8_t>(dst, len), linkType);
        packet_.setTimestamp(layers::Timestamp::currentTime());
    }

    void setData(nonstd::span<const uint8_t> data)
    {
        setData(data.data(), data.size());
    }

    uint8_t* getData() const noexcept
    {
        return data_ + headroom_;
    }

    size_t getLen() const noexcept
    {
        return packet_.getDataLen();
    }

    size_t getCapacity() const noexcept
    {
        return capacity_ >= headroom_ ? capacity_ - headroom_ : 0;
    }

    size_t headroom() const noexcept
    {
        return headroom_;
    }

    uint8_t* getBufferStart() noexcept
    {
        return data_;
    }

    const uint8_t* getBufferStart() const noexcept
    {
        return data_;
    }

    layers::Packet* asPacket() noexcept
    {
        return &packet_;
    }

    const layers::Packet* asPacket() const noexcept
    {
        return &packet_;
    }

    static InMemoryPacket* fromPacket(layers::Packet* packet) noexcept
    {
        if (!packet)
        {
            return nullptr;
        }
        return casket::container_of(packet, &InMemoryPacket::packet_);
    }

    static const InMemoryPacket* fromPacket(const layers::Packet* packet) noexcept
    {
        if (!packet)
        {
            return nullptr;
        }
        return casket::container_of(const_cast<layers::Packet*>(packet), &InMemoryPacket::packet_);
    }

    InMemoryPacket clone() const
    {
        InMemoryPacket copy(capacity_, headroom_);

        const uint8_t* src = packet_.getData();
        size_t n = packet_.getDataLen();

        if (n > 0)
        {
            size_t offset = static_cast<size_t>(src - data_);
            std::memcpy(copy.data_ + offset, src, n);
            copy.packet_.setRawData(nonstd::span<const uint8_t>(copy.data_ + offset, n), packet_.getLinkLayerType());
            copy.packet_.setTimestamp(packet_.getTimestamp());
        }
        return copy;
    }

    std::string toHex() const
    {
        const uint8_t* p = packet_.getData();
        size_t n = packet_.getDataLen();

        std::string result;
        result.reserve(n * 3);
        for (size_t i = 0; i < n; ++i)
        {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%02x ", p[i]);
            result += buf;
        }
        return result;
    }

private:
    layers::Packet packet_;
    std::unique_ptr<uint8_t[]> buffer_;
    size_t capacity_{0};
    size_t headroom_{0};
    uint8_t* data_{nullptr};
};

} // namespace snet::layers