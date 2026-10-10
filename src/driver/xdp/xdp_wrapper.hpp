#pragma once

#include <cstdint>

#include <casket/utils/container_of.hpp>
#include <snet/layers/packet.hpp>

namespace snet::driver
{

class XdpInstance;

/// @brief Zero-copy AF_XDP packet wrapper.
///
/// Unlike AFPacketWrapper, this does NOT point at mmap'd kernel ring memory.
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
    XdpWrapper() = default;
    ~XdpWrapper() noexcept = default;

    XdpWrapper(const XdpWrapper&) = delete;
    XdpWrapper& operator=(const XdpWrapper&) = delete;
    XdpWrapper(XdpWrapper&&) noexcept = default;
    XdpWrapper& operator=(XdpWrapper&&) noexcept = default;

    inline void reset() noexcept
    {
        packet_.clear();
        instance_ = nullptr;
        frameAddr_ = 0;
        caplen_ = 0;
        wirelen_ = 0;
    }

    inline void attach(const uint8_t* data, uint32_t caplen, uint32_t wirelen, XdpInstance* instance,
                       uint64_t frameAddr) noexcept
    {
        packet_.setRawData(data, caplen, layers::LINKTYPE_ETHERNET);
        instance_ = instance;
        frameAddr_ = frameAddr;
        caplen_ = caplen;
        wirelen_ = wirelen;
    }

    static XdpWrapper* fromPacket(layers::Packet* packet) noexcept
    {
        if (!packet)
            return nullptr;
        return casket::container_of(packet, &XdpWrapper::packet_);
    }

    static const XdpWrapper* fromPacket(const layers::Packet* packet) noexcept
    {
        if (!packet)
            return nullptr;
        return casket::container_of(const_cast<layers::Packet*>(packet), &XdpWrapper::packet_);
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
    inline uint64_t frameAddr() const noexcept
    {
        return frameAddr_;
    }
    inline XdpInstance* instance() const noexcept
    {
        return instance_;
    }

private:
    layers::Packet packet_;
    XdpInstance* instance_{nullptr};
    uint64_t frameAddr_{0};
    uint32_t caplen_{0};
    uint32_t wirelen_{0};
};

} // namespace snet::driver