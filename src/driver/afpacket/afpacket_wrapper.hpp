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
/// This wrapper does NOT own the packet data. The data lives in the kernel
/// RX ring mapped into userspace by the driver; the view points directly
/// into that ring.
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
    /// @brief Default constructor. Creates an empty wrapper.
    AFPacketWrapper() = default;

    /// @brief Destructor.
    ~AFPacketWrapper() noexcept = default;

    /// @brief Deleted copy constructor.
    AFPacketWrapper(const AFPacketWrapper&) = delete;

    /// @brief Deleted copy assignment operator.
    AFPacketWrapper& operator=(const AFPacketWrapper&) = delete;

    /// @brief Default move constructor.
    AFPacketWrapper(AFPacketWrapper&&) noexcept = default;

    /// @brief Default move assignment operator.
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
    /// @param[in] data Pointer to the frame payload inside the mmap ring.
    /// @param[in] caplen Captured length in bytes.
    /// @param[in] wirelen Original wire length in bytes.
    /// @param[in] instance Instance that received the frame.
    /// @param[in] entry Ring slot associated with the frame.
    inline void attach(const uint8_t* data, uint32_t caplen, uint32_t wirelen, Instance* instance,
                       RingEntry* entry) noexcept
    {
        packet_.setRawData(data, caplen, layers::LINKTYPE_ETHERNET);
        instance_ = instance;
        entry_ = entry;
        caplen_ = caplen;
        wirelen_ = wirelen;
    }

    /// @brief Recovers the wrapper from an embedded packet pointer.
    /// @param[in] packet Pointer to the embedded packet, may be null.
    /// @return Pointer to the owning wrapper, or nullptr if packet is null.
    static AFPacketWrapper* fromPacket(layers::Packet* packet) noexcept
    {
        if (!packet)
            return nullptr;
        return casket::container_of(packet, &AFPacketWrapper::packet_);
    }

    /// @brief Recovers the wrapper from a const embedded packet pointer.
    /// @param[in] packet Pointer to the embedded packet, may be null.
    /// @return Pointer to the owning wrapper, or nullptr if packet is null.
    static const AFPacketWrapper* fromPacket(const layers::Packet* packet) noexcept
    {
        if (!packet)
            return nullptr;
        return casket::container_of(const_cast<layers::Packet*>(packet), &AFPacketWrapper::packet_);
    }

    /// @brief Gets the embedded packet view.
    /// @return Pointer to the embedded packet.
    inline layers::Packet* asPacket() noexcept
    {
        return &packet_;
    }

    /// @brief Gets the embedded packet view (const).
    /// @return Pointer to the embedded packet.
    inline const layers::Packet* asPacket() const noexcept
    {
        return &packet_;
    }

    /// @brief Gets captured length.
    /// @return Captured length in bytes.
    inline uint32_t caplen() const noexcept
    {
        return caplen_;
    }

    /// @brief Gets original wire length.
    /// @return Wire length in bytes.
    inline uint32_t wirelen() const noexcept
    {
        return wirelen_;
    }

    /// @brief Gets the owning instance.
    /// @return Pointer to the instance that received the frame.
    inline Instance* instance() const noexcept
    {
        return instance_;
    }

    /// @brief Gets the associated ring entry.
    /// @return Pointer to the ring slot to release in finalize.
    inline RingEntry* entry() const noexcept
    {
        return entry_;
    }

private:
    layers::Packet packet_;          ///< Zero-copy view into the mmap frame.
    Instance* instance_{nullptr};    ///< Instance that received the frame.
    RingEntry* entry_{nullptr};      ///< Ring slot to release in finalize.
    uint32_t caplen_{0};             ///< Captured length in bytes.
    uint32_t wirelen_{0};            ///< Original wire length in bytes.
};

} // namespace snet::driver