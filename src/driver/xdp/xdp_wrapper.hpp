#pragma once

#include <cstdint>

#include <casket/utils/container_of.hpp>
#include <snet/layers/packet.hpp>

namespace snet::driver
{

class XdpInstance;

/// @brief Zero-copy AF_XDP packet wrapper.
/// @details Unlike AFPacketWrapper, this does NOT point at mmap'd kernel ring memory.
/// The packet data lives inside the driver's shared UMEM area; the wrapper
/// keeps the frame offset (`frameAddr`) so that:
///   - the same wrapper can be handed back to a *different* instance on TX;
///   - finalizePacket knows exactly where to return the frame.
///
/// Lifetime:
///   - frame is "owned by userspace" while the wrapper is alive;
///   - on finalizePacket() the frame either goes to peer's TX ring or back
///     to the driver's free-frame list.
class XdpWrapper final
{
public:
    /// @brief Constructs an empty wrapper.
    XdpWrapper() = default;

    /// @brief Destroys the wrapper.
    ~XdpWrapper() noexcept = default;

    /// @brief Copy construction is deleted.
    XdpWrapper(const XdpWrapper&) = delete;

    /// @brief Copy assignment is deleted.
    XdpWrapper& operator=(const XdpWrapper&) = delete;

    /// @brief Move constructor (default).
    XdpWrapper(XdpWrapper&&) noexcept = default;

    /// @brief Move assignment (default).
    XdpWrapper& operator=(XdpWrapper&&) noexcept = default;

    /// @brief Resets the wrapper state.
    /// @note Clears the packet view and zeroes instance/frameAddr/caplen/wirelen.
    inline void reset() noexcept
    {
        packet_.clear();
        instance_ = nullptr;
        frameAddr_ = 0;
        caplen_ = 0;
        wirelen_ = 0;
    }

    /// @brief Attaches the wrapper to a UMEM frame.
    /// @param[in] data Pointer to the frame data in UMEM.
    /// @param[in] caplen Captured length.
    /// @param[in] wirelen Original wire length.
    /// @param[in] instance XDP instance owning the frame.
    /// @param[in] frameAddr Frame offset in UMEM.
    inline void attach(const uint8_t* data, uint32_t caplen, uint32_t wirelen, XdpInstance* instance,
                       uint64_t frameAddr) noexcept
    {
        packet_.setRawData(data, caplen, layers::LINKTYPE_ETHERNET);
        instance_ = instance;
        frameAddr_ = frameAddr;
        caplen_ = caplen;
        wirelen_ = wirelen;
    }

    /// @brief Retrieves the wrapper from a Packet.
    /// @param[in] packet Pointer to Packet.
    /// @return Pointer to the wrapper, or nullptr.
    static XdpWrapper* fromPacket(layers::Packet* packet) noexcept
    {
        if (!packet)
            return nullptr;
        return casket::container_of(packet, &XdpWrapper::packet_);
    }

    /// @brief Retrieves the const wrapper from a const Packet.
    /// @param[in] packet Pointer to const Packet.
    /// @return Pointer to the const wrapper, or nullptr.
    static const XdpWrapper* fromPacket(const layers::Packet* packet) noexcept
    {
        if (!packet)
            return nullptr;
        return casket::container_of(const_cast<layers::Packet*>(packet), &XdpWrapper::packet_);
    }

    /// @brief Returns the Packet view.
    /// @return Pointer to Packet.
    inline layers::Packet* asPacket() noexcept
    {
        return &packet_;
    }

    /// @brief Returns the const Packet view.
    /// @return Pointer to const Packet.
    inline const layers::Packet* asPacket() const noexcept
    {
        return &packet_;
    }

    /// @brief Returns the captured length.
    /// @return caplen.
    inline uint32_t caplen() const noexcept
    {
        return caplen_;
    }

    /// @brief Returns the original wire length.
    /// @return wirelen.
    inline uint32_t wirelen() const noexcept
    {
        return wirelen_;
    }

    /// @brief Returns the frame offset in UMEM.
    /// @return frameAddr.
    inline uint64_t frameAddr() const noexcept
    {
        return frameAddr_;
    }

    /// @brief Returns the XDP instance.
    /// @return Pointer to XdpInstance.
    inline XdpInstance* instance() const noexcept
    {
        return instance_;
    }

private:
    /// @brief Packet view over the UMEM frame.
    layers::Packet packet_;

    /// @brief Instance owning the frame.
    XdpInstance* instance_{nullptr};

    /// @brief Frame offset in UMEM.
    uint64_t frameAddr_{0};

    /// @brief Captured length.
    uint32_t caplen_{0};

    /// @brief Original wire length.
    uint32_t wirelen_{0};
};

} // namespace snet::driver