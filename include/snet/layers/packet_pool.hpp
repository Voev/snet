#pragma once
#include <vector>
#include <memory>
#include <snet/io/types.hpp>
#include <casket/types/intrusive_list.hpp>

namespace snet::layers
{

/// @brief Packet pool statistics information
struct PacketPoolInfo
{
    uint32_t size;      ///< Total number of packets in the pool
    uint32_t available; ///< Number of free packets available for acquisition
    size_t memorySize;  ///< Total memory allocated by the pool (objects + data buffers)
};

/// @brief Object pool for packet management with intrusive free list
/// @tparam T Packet type that must have 'data' member and intrusive list hooks (next/prev)
template <class T>
class PacketPool
{
public:
    using Packet = T;                          ///< Packet type alias
    using FreeList = casket::IntrusiveList<T>; ///< Intrusive free list type

public:
    /// @brief Constructs a packet pool with pre-allocated capacity
    /// @param[in] poolSize Number of packets to pre-allocate
    /// @param[in] maxPacketSize Size of data buffer for each packet in bytes
    PacketPool(size_t poolSize, size_t maxPacketSize);

    /// @brief Acquires a packet from the pool
    /// @return Pointer to acquired packet, or nullptr if pool is empty
    T* acquire();

    /// @brief Releases a packet back to the pool
    /// @param[in] p Pointer to the packet to release (nullptr is safely ignored)
    void release(T* p);

    /// @brief Resets all packets to free state
    void clear();

    /// @brief Gets the number of free packets
    /// @return Number of packets currently available
    size_t freeCount() const;

    /// @brief Gets the total number of packets in the pool
    /// @return Total pool capacity
    size_t totalCount() const;

    /// @brief Fills pool statistics information
    /// @param[out] info Reference to PacketPoolInfo structure to be filled
    void getInfo(PacketPoolInfo& info) const;

private:
    std::vector<std::unique_ptr<uint8_t[]>> buffers_; ///< Data buffers storage
    std::vector<std::unique_ptr<T>> packets_;         ///< Packet objects storage
    FreeList freeList_;                               ///< Intrusive list of free packets
    size_t maxPacketSize_;                            ///< Size of each data buffer
};

// Implementation

template <class T>
PacketPool<T>::PacketPool(size_t poolSize, size_t maxPacketSize)
    : maxPacketSize_(maxPacketSize)
{
    packets_.reserve(poolSize);
    buffers_.reserve(poolSize);

    for (size_t i = 0; i < poolSize; ++i)
    {
        auto buffer = std::make_unique<uint8_t[]>(maxPacketSize);
        uint8_t* dataPtr = buffer.get();
        buffers_.push_back(std::move(buffer));

        auto packet = std::make_unique<T>();
        packet->data = dataPtr;

        freeList_.push_back(*packet);
        packets_.push_back(std::move(packet));
    }
}

template <class T>
T* PacketPool<T>::acquire()
{
    T* p = freeList_.pop_front();
    if (!p)
    {
        return nullptr;
    }
    return p;
}

template <class T>
void PacketPool<T>::release(T* p)
{
    if (p)
    {
        freeList_.push_back(*p);
    }
}

template <class T>
void PacketPool<T>::clear()
{
    while (auto* p = freeList_.pop_front())
    {
        (void)p;
    }

    for (auto& packet_ptr : packets_)
    {
        if (packet_ptr)
        {
            packet_ptr->next = nullptr;
            packet_ptr->prev = nullptr;
            freeList_.push_back(*packet_ptr);
        }
    }
}

template <class T>
size_t PacketPool<T>::freeCount() const
{
    return freeList_.size();
}

template <class T>
size_t PacketPool<T>::totalCount() const
{
    return packets_.size();
}

template <class T>
void PacketPool<T>::getInfo(PacketPoolInfo& info) const
{
    info.size = static_cast<uint32_t>(packets_.size());
    info.available = static_cast<uint32_t>(freeList_.size());
    info.memorySize = packets_.size() * (sizeof(T) + maxPacketSize_);
}

} // namespace snet::layers