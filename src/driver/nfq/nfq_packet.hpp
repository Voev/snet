#pragma once
#include <linux/netfilter.h>

#include <snet/layers/packet.hpp>

namespace snet::driver
{

/// @brief Netfilter queue packet wrapper with intrusive list support.
struct NfqPacket final
{
    layers::Packet packet;
    std::unique_ptr<uint8_t[]> buffer_; ///< Owned data buffer.
    size_t capacity_{0};                ///< Buffer size.
    const nlmsghdr* mh{nullptr};        ///< Netlink message header
    nfqnl_msg_packet_hdr* ph{nullptr};  ///< Netfilter queue packet header
    uint8_t* data{nullptr};             ///< Raw packet data pointer

    /// @brief Default constructor.
    NfqPacket() = default;

    /// @brief Constructor with buffer allocation.
    /// Called by FixedObjectPool when creating each packet in the pool.
    /// @param maxPacketSize Size of the data buffer to allocate.
    explicit NfqPacket(size_t maxPacketSize)
    {
        allocate(maxPacketSize);
    }

    NfqPacket(const NfqPacket&) = delete;
    NfqPacket& operator=(const NfqPacket&) = delete;

    NfqPacket(NfqPacket&&) = default;
    NfqPacket& operator=(NfqPacket&&) = default;

    void allocate(size_t size)
    {
        if (size > capacity_)
        {
            buffer_ = std::make_unique<uint8_t[]>(size);
            data = buffer_.get();
            capacity_ = size;
            packet.setRawData(nonstd::span<const uint8_t>(data, size));
        }
    }

    /// @brief Gets the parent wrapper from an embedded Packet pointer.
    ///
    /// @param[in] packet Pointer to the embedded Packet.
    ///
    /// @return Pointer to the parent wrapper, or nullptr if input is null.
    static NfqPacket* fromPacket(layers::Packet* packet) noexcept
    {
        if (!packet)
        {
            return nullptr;
        }
        return casket::container_of(packet, &NfqPacket::packet);
    }
};

} // namespace snet::driver