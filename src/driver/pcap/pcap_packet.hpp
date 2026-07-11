#pragma once
#include <cstdint>
#include <cstring>
#include <memory>
#include <pcap.h>
#include <snet/layers/packet_wrapper.hpp>
#include <snet/layers/timestamp.hpp>

namespace snet::driver
{

/// @brief PCAP packet wrapper.
/// Owns and manages its own data buffer allocated from the pool.
struct PcapPacket final : public layers::PacketWrapper<PcapPacket>
{
    /// Owned data buffer.
    std::unique_ptr<uint8_t[]> buffer_;

    /// Buffer size in bytes.
    size_t capacity_{0};

    /// Pointer to buffer data.
    uint8_t* data{nullptr};

    /// PCAP packet header.
    struct pcap_pkthdr header{};

    /// @brief Default constructor.
    PcapPacket() = default;

    /// @brief Constructor with buffer allocation.
    /// Called by FixedObjectPool when creating each packet in the pool.
    /// @param maxPacketSize Size of the data buffer to allocate.
    explicit PcapPacket(size_t maxPacketSize)
    {
        allocate(maxPacketSize);
    }

    PcapPacket(PcapPacket&&) = default;

    PcapPacket& operator=(PcapPacket&&) = default;

    /// @brief Allocates a data buffer.
    /// If the requested size is larger than the current capacity,
    /// a new buffer is allocated and the data pointer is updated.
    /// @param size Buffer size in bytes.
    void allocate(size_t size)
    {
        if (size > capacity_)
        {
            buffer_ = std::make_unique<uint8_t[]>(size);
            data = buffer_.get();
            capacity_ = size;
        }
    }

    /// @brief Resets the packet for reuse.
    /// Clears the Packet viewer and the PCAP header.
    /// The data buffer remains allocated.
    void reset() noexcept override
    {
        PacketWrapper::reset();
        memset(&header, 0, sizeof(header));
    }

    /// @brief Copies data from PCAP into the owned buffer.
    /// @param hdr PCAP packet header.
    /// @param rawData Raw packet data from PCAP.
    /// @param maxLen Maximum number of bytes to copy.
    void setFromPcap(const struct pcap_pkthdr* hdr, const uint8_t* rawData, size_t maxLen)
    {
        if (!hdr || !rawData || !data)
            return;

        header = *hdr;

        size_t len = std::min(static_cast<size_t>(hdr->caplen), maxLen);
        if (len > 0 && len <= capacity_)
        {
            memcpy(data, rawData, len);
            packet.setRawData(nonstd::span<const uint8_t>(data, len), layers::LINKTYPE_ETHERNET);
            packet.setTimestamp(layers::Timestamp(hdr->ts));
        }
    }

    /// @brief Returns a pointer to the mutable data buffer.
    uint8_t* getData() noexcept
    {
        return data;
    }

    /// @brief Returns the buffer capacity.
    size_t getCapacity() const noexcept
    {
        return capacity_;
    }

    /// @brief Returns the PCAP packet header.
    const struct pcap_pkthdr& getHeader() const noexcept
    {
        return header;
    }
};

} // namespace snet::driver