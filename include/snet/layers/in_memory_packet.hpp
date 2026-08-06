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
    InMemoryPacket() = default;

    explicit InMemoryPacket(size_t maxPacketSize)
    {
        allocate(maxPacketSize);
    }

    ~InMemoryPacket() noexcept = default;

    InMemoryPacket(const InMemoryPacket&) = delete;
    InMemoryPacket& operator=(const InMemoryPacket&) = delete;

    InMemoryPacket(InMemoryPacket&& other) noexcept
        : packet_(std::move(other.packet_))
        , buffer_(std::move(other.buffer_))
        , capacity_(other.capacity_)
        , data_(other.data_)
        , len_(other.len_)
    {
        other.data_ = nullptr;
        other.len_ = 0;
        other.capacity_ = 0;
    }

    InMemoryPacket& operator=(InMemoryPacket&& other) noexcept
    {
        if (this != &other)
        {
            packet_ = std::move(other.packet_);
            buffer_ = std::move(other.buffer_);
            capacity_ = other.capacity_;
            data_ = other.data_;
            len_ = other.len_;

            other.data_ = nullptr;
            other.len_ = 0;
            other.capacity_ = 0;
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
            len_ = 0;
            packet_.clear();
        }
    }

    void reset() noexcept
    {
        packet_.clear();
        len_ = 0;
        // data_ remains allocated
    }

    void setData(const uint8_t* data, size_t len)
    {
        if (!data || len == 0 || len > capacity_)
            return;

        std::memcpy(data_, data, len);
        len_ = len;
        packet_.setRawData(nonstd::span<const uint8_t>(data_, len_), layers::LINKTYPE_ETHERNET);
        packet_.setTimestamp(layers::Timestamp::currentTime());
    }

    void setData(nonstd::span<const uint8_t> data)
    {
        setData(data.data(), data.size());
    }

    uint8_t* getData() const noexcept
    {
        return data_;
    }

    size_t getLen() const noexcept
    {
        return len_;
    }

    size_t getCapacity() const noexcept
    {
        return capacity_;
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
        InMemoryPacket copy(capacity_);
        if (len_ > 0)
        {
            std::memcpy(copy.data_, data_, len_);
            copy.len_ = len_;
            copy.packet_.setRawData(nonstd::span<const uint8_t>(copy.data_, len_), packet_.getLinkLayerType());
            copy.packet_.setTimestamp(packet_.getTimestamp());
        }
        return copy;
    }

    std::string toHex() const
    {
        std::string result;
        result.reserve(len_ * 3);
        for (size_t i = 0; i < len_; ++i)
        {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%02x ", data_[i]);
            result += buf;
        }
        return result;
    }

private:
    layers::Packet packet_;
    std::unique_ptr<uint8_t[]> buffer_;
    size_t capacity_{0};
    uint8_t* data_{nullptr};
    size_t len_{0};
};

} // namespace snet::layers