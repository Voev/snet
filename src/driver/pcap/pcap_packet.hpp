#pragma once
#include <cstdint>
#include <cstring>
#include <memory>
#include <pcap.h>
#include <casket/utils/container_of.hpp>
#include <snet/layers/packet.hpp>
#include <snet/layers/timestamp.hpp>

namespace snet::driver
{

/// @brief PCAP packet wrapper that owns a data buffer and provides packet viewing capabilities.
///
/// This class encapsulates a raw packet buffer and provides methods for:
/// - Allocating and managing packet data storage.
/// - Filling packet data from PCAP capture sources.
/// - Accessing the embedded packet viewer for protocol parsing and modification.
///
/// The class is designed to be used with casket::FixedObjectPool for efficient
/// memory management and zero-copy operations.
///
/// @note Instances are non-copyable but movable.
/// @note The embedded Packet is a non-owning viewer that references the internal buffer.
///
/// @code
///   PcapPacket pkt(2048);  // Allocate 2048 bytes buffer.
///   pkt.setFromPcap(hdr, data);
///   layers::Packet* viewer = pkt.asPacket();
///   // ... process viewer ...
/// @endcode
class PcapPacket final
{
public:
    /// @brief Default constructor. Creates an empty packet with no buffer.
    PcapPacket() = default;

    /// @brief Deleted copy constructor. Packets cannot be copied.
    PcapPacket(const PcapPacket&) = delete;

    /// @brief Deleted copy assignment operator. Packets cannot be copied.
    PcapPacket& operator=(const PcapPacket&) = delete;

    /// @brief Default move constructor. Transfers ownership of the buffer.
    PcapPacket(PcapPacket&&) noexcept = default;

    /// @brief Default move assignment operator. Transfers ownership of the buffer.
    PcapPacket& operator=(PcapPacket&&) noexcept = default;

    /// @brief Constructs a packet with a pre-allocated data buffer.
    ///
    /// @param maxPacketSize Size of the data buffer to allocate in bytes.
    /// @throws std::bad_alloc if memory allocation fails.
    explicit PcapPacket(size_t maxPacketSize)
    {
        allocate(maxPacketSize);
    }

    /// @brief Default destructor. Releases the owned buffer.
    ~PcapPacket() noexcept = default;

    /// @brief Allocates or reallocates the internal data buffer.
    ///
    /// If the requested size exceeds the current capacity, a new buffer is allocated
    /// and the old one is replaced. Existing data is not preserved.
    ///
    /// @param size Buffer size in bytes.
    /// @throws std::bad_alloc if memory allocation fails.
    inline void allocate(size_t size)
    {
        if (size > capacity_)
        {
            buffer_ = std::make_unique<uint8_t[]>(size);
            capacity_ = size;
        }
    }

    /// @brief Resets the packet to an empty state for reuse.
    ///
    /// Clears the embedded packet viewer and timestamp. The data buffer remains
    /// allocated and is not deallocated.
    ///
    /// @note Never throws exceptions.
    inline void reset() noexcept
    {
        packet_.clear();
    }

    /// @brief Fills the packet from PCAP capture data.
    ///
    /// Copies the raw packet data into the internal buffer and updates the embedded
    /// packet viewer to reference the copied data. The timestamp is preserved from
    /// the PCAP header.
    ///
    /// @param hdr PCAP packet header containing timestamp and length information.
    /// @param rawData Raw packet data bytes from the PCAP capture.
    /// @throws May throw from layers::Packet::setRawData.
    inline void setFromPcap(const struct pcap_pkthdr& hdr, const uint8_t* rawData)
    {
        if (!rawData || !buffer_)
            return;

        const size_t len = std::min(static_cast<size_t>(hdr.caplen), capacity_);
        if (len > 0)
        {
            std::memcpy(buffer_.get(), rawData, len);
            packet_.setRawData(nonstd::span<const uint8_t>(buffer_.get(), len), layers::LINKTYPE_ETHERNET);
            packet_.setTimestamp(layers::Timestamp(hdr.ts));
        }
    }

    /// @brief Retrieves the parent PcapPacket from an embedded Packet pointer.
    ///
    /// This is a safe down-casting method that uses container_of to compute
    /// the parent object address from a pointer to its embedded member.
    ///
    /// @param packet Pointer to the embedded Packet object.
    /// @return Pointer to the containing PcapPacket, or nullptr if input is null.
    /// @note Never throws exceptions.
    static inline PcapPacket* fromPacket(layers::Packet* packet) noexcept
    {
        if (!packet)
        {
            return nullptr;
        }
        return casket::container_of(packet, &PcapPacket::packet_);
    }

    /// @brief Const version of fromPacket.
    ///
    /// @param packet Const pointer to the embedded Packet object.
    /// @return Const pointer to the containing PcapPacket, or nullptr if input is null.
    /// @note Never throws exceptions.
    static inline const PcapPacket* fromPacket(const layers::Packet* packet) noexcept
    {
        if (!packet)
        {
            return nullptr;
        }
        return casket::container_of(const_cast<layers::Packet*>(packet), &PcapPacket::packet_);
    }

    /// @brief Returns a pointer to the embedded Packet viewer.
    ///
    /// The returned Packet provides read/write access to the packet data through
    /// protocol headers and payload spans.
    ///
    /// @return Pointer to the embedded Packet.
    /// @note Never throws exceptions.
    inline layers::Packet* asPacket() noexcept
    {
        return &packet_;
    }

    /// @brief Const version of asPacket.
    ///
    /// @return Const pointer to the embedded Packet.
    /// @note Never throws exceptions.
    inline const layers::Packet* asPacket() const noexcept
    {
        return &packet_;
    }

    /// @brief Returns a pointer to the internal data buffer.
    ///
    /// @return Pointer to the raw packet data buffer, or nullptr if not allocated.
    /// @note Never throws exceptions.
    inline uint8_t* getData() const noexcept
    {
        return buffer_.get();
    }

    /// @brief Returns the current buffer capacity in bytes.
    ///
    /// @return Size of the allocated data buffer.
    /// @note Never throws exceptions.
    inline size_t getCapacity() const noexcept
    {
        return capacity_;
    }

private:
    layers::Packet packet_;             ///< Embedded packet viewer.
    std::unique_ptr<uint8_t[]> buffer_; ///< Owned data buffer.
    size_t capacity_{0UL};              ///< Buffer capacity in bytes.
};

} // namespace snet::driver