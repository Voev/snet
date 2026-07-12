#pragma once
#include <linux/netfilter.h>

#include <snet/layers/packet.hpp>

#include "nl_messages.hpp"

namespace snet::driver
{

/// @brief Netfilter queue packet wrapper with intrusive list support.
/// 
/// This class encapsulates a packet received from Netfilter queue (NFQUEUE) via Netlink socket.
/// It manages the raw packet data buffer and provides access to parsed protocol layers.
/// The packet data is stored in a pre-allocated buffer for performance optimization
/// with object pooling.
///
/// @note This class is non-copyable but movable.
/// @note All TCP/IP protocol processing is handled by the application layer,
///       not by the kernel's network stack.
class NfqPacket final
{
public:
    /// @brief Default constructor.
    /// Creates an empty packet wrapper without allocated buffer.
    NfqPacket() = default;

    /// @brief Destructor.
    /// Releases the owned data buffer.
    ~NfqPacket() noexcept = default;

    /// @brief Copy constructor is deleted (non-copyable).
    NfqPacket(const NfqPacket&) = delete;

    /// @brief Copy assignment operator is deleted (non-copyable).
    NfqPacket& operator=(const NfqPacket&) = delete;

    /// @brief Move constructor.
    NfqPacket(NfqPacket&&) = default;

    /// @brief Move assignment operator.
    NfqPacket& operator=(NfqPacket&&) = default;

    /// @brief Constructor with buffer allocation.
    /// Called by FixedObjectPool when creating each packet in the pool.
    /// @param maxPacketSize Size of the data buffer to allocate in bytes.
    explicit NfqPacket(size_t maxPacketSize)
    {
        allocate(maxPacketSize);
    }

    /// @brief Allocate or reallocate the internal data buffer.
    /// If the requested size is larger than current capacity, a new buffer is allocated.
    /// @param size Required buffer size in bytes.
    void allocate(size_t size)
    {
        if (size > capacity_)
        {
            buffer_ = std::make_unique<uint8_t[]>(size);
            capacity_ = size;
        }
    }

    /// @brief Reset the packet to initial empty state.
    /// Clears all packet data, headers and metadata.
    /// Used when returning the object to the pool.
    inline void reset() noexcept
    {
        packet_.clear();
        ph_ = nullptr;
        mh_ = nullptr;
    }

    /// @brief Get the containing NfqPacket from a Packet pointer.
    /// Uses intrusive container mechanics to retrieve the parent object.
    /// @param packet Pointer to the embedded Packet object.
    /// @return Pointer to the containing NfqPacket, or nullptr if input is null.
    static NfqPacket* fromPacket(layers::Packet* packet) noexcept
    {
        if (!packet)
        {
            return nullptr;
        }
        return casket::container_of(packet, &NfqPacket::packet_);
    }

    /// @brief Get the containing NfqPacket from a const Packet pointer.
    /// @param packet Pointer to the embedded Packet object.
    /// @return Pointer to the containing NfqPacket, or nullptr if input is null.
    static inline const NfqPacket* fromPacket(const layers::Packet* packet) noexcept
    {
        if (!packet)
        {
            return nullptr;
        }
        return casket::container_of(const_cast<layers::Packet*>(packet), &NfqPacket::packet_);
    }

    /// @brief Get the embedded Packet object for manipulation.
    /// @return Pointer to the Packet object.
    inline layers::Packet* asPacket() noexcept
    {
        return &packet_;
    }

    /// @brief Get the embedded Packet object for read-only access.
    /// @return Pointer to the const Packet object.
    inline const layers::Packet* asPacket() const noexcept
    {
        return &packet_;
    }

    /// @brief Get the Netfilter packet ID.
    /// This ID is used for verdict responses (accept, drop, etc.).
    /// @return Packet ID in host byte order, or 0 if not available.
    inline uint32_t getPacketId() const noexcept
    {
        if (ph_)
        {
            return ntohl(ph_->packet_id);
        }
        return 0U;
    }

    /// @brief Get the raw packet data buffer.
    /// @return Pointer to the internal data buffer, or nullptr if not allocated.
    inline uint8_t* getData() const noexcept
    {
        return buffer_.get();
    }

    /// @brief Get the current buffer capacity.
    /// @return Size of the allocated buffer in bytes.
    inline size_t getCapacity() const noexcept
    {
        return capacity_;
    }

    /// @brief Initialize the packet from a Netlink message.
    /// Parses the Netlink message, extracts packet data and metadata,
    /// and stores them in the internal structures.
    ///
    /// @param nlh Pointer to the Netlink message header.
    /// @return true if the packet was successfully initialized, false otherwise.
    ///
    /// @note The packet must not be already initialized (mh_ must be nullptr).
    /// @note The data is copied into the internal buffer for persistence.
    bool setFromMessage(const nlmsghdr* nlh);

private:
    layers::Packet packet_;              ///< Protocol layer parser and accessor.
    std::unique_ptr<uint8_t[]> buffer_;  ///< Owned raw packet data buffer.
    size_t capacity_{0};                 ///< Allocated buffer size in bytes.
    const nlmsghdr* mh_{nullptr};        ///< Netlink message header.
    nfqnl_msg_packet_hdr* ph_{nullptr};  ///< Netfilter queue packet header.
};

} // namespace snet::driver