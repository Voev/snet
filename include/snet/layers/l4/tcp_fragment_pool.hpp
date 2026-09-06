// snet/layers/l4/tcp_fragment_pool.hpp
#pragma once
#include <snet/layers/l4/tcp_fragment.hpp>
#include <casket/types/fixed_object_pool.hpp>
#include <chrono>
#include <cstring>

namespace snet::layers
{

/// @brief Configuration for TcpFragmentPool.
struct TcpFragmentPoolConfig
{
    size_t poolSize{4096};          ///< Maximum number of fragments.
    size_t maxDataSize{2048};       ///< Maximum data size per fragment.
    bool enableStats{false};        ///< Enable statistics collection.
};

/// @brief High-performance pool for TCP fragments.
class TcpFragmentPool
{
public:
    using FragmentPool = casket::FixedObjectPool<TcpFragment>;

    explicit TcpFragmentPool(const TcpFragmentPoolConfig& config = TcpFragmentPoolConfig())
        : config_(config)
        , pool_(config.poolSize, config.maxDataSize)
    {
        // FixedObjectPool создаст все фрагменты с конструктором TcpFragment(size_t)
        // который выделит data буфер нужного размера
    }

    ~TcpFragmentPool() = default;

    // Запрещаем копирование
    TcpFragmentPool(const TcpFragmentPool&) = delete;
    TcpFragmentPool& operator=(const TcpFragmentPool&) = delete;

    // Разрешаем перемещение
    TcpFragmentPool(TcpFragmentPool&&) = default;
    TcpFragmentPool& operator=(TcpFragmentPool&&) = default;

    // ====== ACQUIRE ======

    /// @brief Acquire a fragment from the pool.
    /// @param seq TCP sequence number.
    /// @param data Pointer to data to copy.
    /// @param len Length of data.
    /// @param ts Timestamp of the packet.
    /// @return Pointer to fragment, or nullptr if pool is exhausted.
    TcpFragment* acquire(uint32_t seq, const uint8_t* data, size_t len,
                         std::chrono::time_point<std::chrono::high_resolution_clock> ts)
    {
        if (len > config_.maxDataSize)
        {
            if (config_.enableStats)
                ++stats_.oversizedDrops;
            return nullptr;
        }

        TcpFragment* frag = pool_.acquire();
        if (!frag)
        {
            if (config_.enableStats)
                ++stats_.exhaustedDrops;
            return nullptr;
        }

        frag->sequence = seq;
        frag->dataLength = len;
        frag->timestamp = ts;

        if (data && len > 0)
        {
            std::memcpy(frag->data, data, len);
        }

        if (config_.enableStats)
        {
            ++stats_.acquired;
            stats_.totalBytes += len;
        }

        return frag;
    }

    /// @brief Acquire a fragment without copying data (for zero-copy).
    /// @param seq TCP sequence number.
    /// @param data Pointer to data (ownership transferred!).
    /// @param len Length of data.
    /// @param ts Timestamp of the packet.
    /// @return Pointer to fragment, or nullptr if pool is exhausted.
    TcpFragment* acquireZeroCopy(uint32_t seq, uint8_t* data, size_t len,
                                 std::chrono::time_point<std::chrono::high_resolution_clock> ts)
    {
        if (len > config_.maxDataSize)
        {
            if (config_.enableStats)
                ++stats_.oversizedDrops;
            delete[] data;
            return nullptr;
        }

        TcpFragment* frag = pool_.acquire();
        if (!frag)
        {
            if (config_.enableStats)
                ++stats_.exhaustedDrops;
            delete[] data;
            return nullptr;
        }

        // Перемещаем владение данными
        delete[] frag->data;
        frag->data = data;
        frag->sequence = seq;
        frag->dataLength = len;
        frag->timestamp = ts;

        if (config_.enableStats)
        {
            ++stats_.acquired;
            stats_.totalBytes += len;
        }

        return frag;
    }

    // ====== RELEASE ======

    /// @brief Release a fragment back to the pool.
    void release(TcpFragment* frag)
    {
        if (!frag)
            return;

        frag->reset();
        pool_.release(frag);

        if (config_.enableStats)
        {
            ++stats_.released;
        }
    }

    /// @brief Release all fragments in a map.
    template<typename MapType>
    void releaseAll(MapType& fragMap)
    {
        for (auto& pair : fragMap)
        {
            release(pair.second);
        }
        fragMap.clear();
    }

    // ====== ACCESSORS ======

    /// @brief Get the number of free fragments.
    size_t freeCount() const
    {
        return pool_.poolSize() - stats_.acquired + stats_.released;
    }

    /// @brief Get the total number of fragments.
    size_t totalCount() const
    {
        return pool_.poolSize();
    }

    /// @brief Get the maximum data size.
    size_t maxDataSize() const
    {
        return config_.maxDataSize;
    }

    /// @brief Get statistics.
    struct Stats
    {
        size_t acquired{0};
        size_t released{0};
        size_t totalBytes{0};
        size_t exhaustedDrops{0};
        size_t oversizedDrops{0};
    };

    Stats getStats() const
    {
        return stats_;
    }

    void resetStats()
    {
        stats_ = Stats{};
    }

private:
    TcpFragmentPoolConfig config_;
    FragmentPool pool_;
    Stats stats_;
};

} // namespace snet::layers