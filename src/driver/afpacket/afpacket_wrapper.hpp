#pragma once

#include <cstdint>

#include <casket/utils/container_of.hpp>

#include <snet/layers/packet.hpp>

namespace snet::driver
{

class Instance;
struct RingEntry;

/// @brief AF_PACKET packet wrapper for zero-copy access to mmap ring frames.
///
/// Unlike NfqPacket, this wrapper does NOT own the packet data. The data
/// lives in the kernel RX ring mapped into userspace by the driver; the
/// view points directly into that ring.
///
/// Lifetime rules:
///   - The frame stays marked TP_STATUS_USER while this wrapper is alive.
///   - The frame is returned to the kernel via AFPacketDriver::finalizePacket()
///     (which sets TP_STATUS_KERNEL).
///   - After finalize, neither this wrapper nor the embedded layers::Packet
///     may be used.
///
/// Non-copyable, movable, intended to be pooled.
class AFPacketWrapper final
{
public:
    AFPacketWrapper() = default;
    ~AFPacketWrapper() noexcept = default;

    AFPacketWrapper(const AFPacketWrapper&) = delete;
    AFPacketWrapper& operator=(const AFPacketWrapper&) = delete;
    AFPacketWrapper(AFPacketWrapper&&) noexcept = default;
    AFPacketWrapper& operator=(AFPacketWrapper&&) noexcept = default;

    /// @brief Reset to empty state (called on pool return).
    inline void reset() noexcept
    {
        packet_.clear();
        entry_ = nullptr;
        instance_ = nullptr;
        caplen_ = 0;
        wirelen_ = 0;
    }

    /// @brief Attach to a ring frame (zero-copy).
    inline void attach(const uint8_t* data, uint32_t caplen, uint32_t wirelen, Instance* instance,
                       RingEntry* entry) noexcept
    {
        packet_.setRawData(data, caplen, layers::LINKTYPE_ETHERNET);
        instance_ = instance;
        entry_ = entry;
        caplen_ = caplen;
        wirelen_ = wirelen;
    }

    static AFPacketWrapper* fromPacket(layers::Packet* packet) noexcept
    {
        if (!packet)
            return nullptr;
        return casket::container_of(packet, &AFPacketWrapper::packet_);
    }

    static const AFPacketWrapper* fromPacket(const layers::Packet* packet) noexcept
    {
        if (!packet)
            return nullptr;
        return casket::container_of(const_cast<layers::Packet*>(packet), &AFPacketWrapper::packet_);
    }

    inline layers::Packet* asPacket() noexcept
    {
        return &packet_;
    }
    inline const layers::Packet* asPacket() const noexcept
    {
        return &packet_;
    }

    inline uint32_t caplen() const noexcept
    {
        return caplen_;
    }
    inline uint32_t wirelen() const noexcept
    {
        return wirelen_;
    }
    inline Instance* instance() const noexcept
    {
        return instance_;
    }
    inline RingEntry* entry() const noexcept
    {
        return entry_;
    }

private:
    layers::Packet packet_; ///< Zero-copy view into the mmap frame.
    Instance* instance_{nullptr};
    RingEntry* entry_{nullptr}; ///< Ring slot to release in finalize.
    uint32_t caplen_{0};
    uint32_t wirelen_{0};
};

} // namespace snet::driver