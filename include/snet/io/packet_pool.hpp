#pragma once
#include <vector>
#include <stack>
#include <memory>
#include <stdexcept>
#include <snet/io/types.hpp>

namespace snet::io
{

template <class T>
class PacketPool final
{
public:
    PacketPool() = default;

    ~PacketPool() noexcept
    {
        deallocatePool();
    }

    void allocatePool(std::size_t size)
    {
        pool_.reserve(size);
        for (std::size_t i = 0; i < size; ++i)
        {
            pool_.emplace_back(std::make_unique<T>());
            freelist_.push(pool_.back().get());
        }
        info_.size = size;
        info_.available = size;
        info_.memorySize = sizeof(T) * size;
    }

    void deallocatePool() noexcept
    {
        while (!freelist_.empty())
        {
            freelist_.pop();
        }
        pool_.clear();
        info_.size = 0;
        info_.available = 0;
        info_.memorySize = 0;
    }

    T* acquirePacket() noexcept
    {
        if (freelist_.empty())
        {
            return nullptr;
        }

        T* packet = freelist_.top();
        freelist_.pop();
        info_.available--;
        return packet;
    }

    void releasePacket(T* packet) noexcept
    {
        if (packet)
        {
            freelist_.push(packet);
            info_.available++;
        }
    }

    const PacketPoolInfo& getPoolInfo() const noexcept
    {
        return info_;
    }

private:
    std::vector<std::unique_ptr<T>> pool_; ///< Object pool
    std::stack<T*> freelist_;              ///< Free objects
    PacketPoolInfo info_;                  ///< Pool memory info
};

} // namespace snet::io