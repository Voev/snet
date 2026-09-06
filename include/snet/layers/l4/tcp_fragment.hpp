#pragma once
#include <cstdint>
#include <chrono>
#include <cstring>

namespace snet::layers
{

/// @brief TCP fragment for out-of-order reassembly.
struct TcpFragment
{
    uint32_t sequence{0};
    size_t dataLength{0};
    uint8_t* data{nullptr};
    std::chrono::time_point<std::chrono::high_resolution_clock> timestamp;

    TcpFragment() = default;

    TcpFragment(size_t len)
        : dataLength(len)
    {
        if (len > 0)
        {
            data = new uint8_t[len];
        }
    }

    ~TcpFragment()
    {
        delete[] data;
    }

    TcpFragment(const TcpFragment&) = delete;
    TcpFragment& operator=(const TcpFragment&) = delete;

    TcpFragment(TcpFragment&& other) noexcept
        : sequence(other.sequence)
        , dataLength(other.dataLength)
        , data(other.data)
        , timestamp(other.timestamp)
    {
        other.data = nullptr;
        other.dataLength = 0;
    }

    TcpFragment& operator=(TcpFragment&& other) noexcept
    {
        if (this != &other)
        {
            delete[] data;
            sequence = other.sequence;
            dataLength = other.dataLength;
            data = other.data;
            timestamp = other.timestamp;
            other.data = nullptr;
            other.dataLength = 0;
        }
        return *this;
    }

    /// @brief Reset for pool reuse.
    void reset() noexcept
    {
        sequence = 0;
        dataLength = 0;
        // data не очищается — он будет перезаписан при следующем использовании
    }

    bool hasData() const
    {
        return data != nullptr && dataLength > 0;
    }
    uint32_t endSequence() const
    {
        return sequence + static_cast<uint32_t>(dataLength);
    }
};

} // namespace snet::layers