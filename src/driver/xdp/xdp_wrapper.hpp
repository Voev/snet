#pragma once

#include <cstdint>

#include <casket/utils/container_of.hpp>

#include <snet/layers/packet.hpp>

namespace snet::driver
{

class XdpDriver;
struct XdpInstance;

/// AF_XDP packet wrapper for zero-copy access to UMEM frames.
///
/// The data lives in the UMEM shared between kernel and userspace.
/// Lifetime rules:
///   - The UMEM frame is owned by the driver while this wrapper is alive.
///   - The frame is returned to the fill ring via XdpDriver::releaseFrame(),
///     which is called from XdpDriver::finalizePacket() when the frame was
///     not forwarded through a peer interface.
///   - If the frame was forwarded to a peer TX ring, the kernel returns it
///     to the fill ring via the completion ring instead.
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
        frameAddr_ = 0;
        caplen_ = 0;
        wirelen_ = 0;
        instance_ = nullptr;
    }

    inline void attach(const uint8_t* data, uint32_t caplen, uint32_t wirelen,
                       uint64_t frameAddr, XdpInstance* instance) noexcept
    {
        packet_.setRawData(data, caplen, layers::LINKTYPE_ETHERNET);
        frameAddr_ = frameAddr;
        caplen_ = caplen;
        wirelen_ = wirelen;
        instance_ = instance;
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

    inline layers::Packet* asPacket() noexcept { return &packet_; }
    inline const layers::Packet* asPacket() const noexcept { return &packet_; }

    inline uint32_t caplen() const noexcept { return caplen_; }
    inline uint32_t wirelen() const noexcept { return wirelen_; }
    inline uint64_t frameAddr() const noexcept { return frameAddr_; }
    inline XdpInstance* instance() const noexcept { return instance_; }

private:
    layers::Packet packet_;
    uint64_t frameAddr_{0};
    uint32_t caplen_{0};
    uint32_t wirelen_{0};
    XdpInstance* instance_{nullptr};
};

} // namespace snet::driver