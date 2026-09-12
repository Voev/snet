#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>

namespace snet
{

/// @brief Transport transmit ring buffer.
///
/// Application writes data via write().
/// sTransport sender drains into packets.
/// Data retained until ACKed (for retransmit).
class TxRingBuffer
{
public:
    static constexpr size_t DEFAULT_CAPACITY = 64 * 1024;
    static constexpr size_t MAX_CAPACITY = 4 * 1024 * 1024;

    explicit TxRingBuffer(size_t capacity = DEFAULT_CAPACITY)
        : capacity_(std::min(capacity, MAX_CAPACITY))
        , buffer_(capacity_)
        , writePos_(0)
        , readPos_(0)
        , ackedPos_(0)
        , seqBase_(0)
        , initialized_(false)
    {
    }

    void initAt(uint32_t seq) noexcept
    {
        seqBase_ = seq;
        writePos_ = readPos_ = ackedPos_ = 0;
        initialized_ = true;
    }

    size_t write(const uint8_t* data, size_t len) noexcept
    {
        if (!initialized_)
            return 0;
        const size_t free = capacity_ - (writePos_ - ackedPos_);
        const size_t toWrite = std::min(len, free);
        if (toWrite == 0)
            return 0;

        const size_t offset = writePos_ % capacity_;
        const size_t firstChunk = std::min(toWrite, capacity_ - offset);

        std::memcpy(buffer_.data() + offset, data, firstChunk);
        if (firstChunk < toWrite)
            std::memcpy(buffer_.data(), data + firstChunk, toWrite - firstChunk);

        writePos_ += toWrite;
        return toWrite;
    }

    /// @brief Zero-copy peek of next chunk to send.
    std::pair<const uint8_t*, size_t> peek() const noexcept
    {
        const size_t pending = writePos_ - readPos_;
        if (pending == 0)
            return {nullptr, 0};
        const size_t offset = readPos_ % capacity_;
        const size_t firstChunk = std::min(pending, capacity_ - offset);
        return {buffer_.data() + offset, firstChunk};
    }

    /// @brief Marks n bytes as sent (moves read pointer).
    void advance(size_t n) noexcept
    {
        const size_t pending = writePos_ - readPos_;
        readPos_ += std::min(n, pending);
    }

    /// @brief Marks n bytes as ACKed (frees space).
    void ack(size_t n) noexcept
    {
        const size_t unacked = writePos_ - ackedPos_;
        ackedPos_ += std::min(n, unacked);
    }

    /// @brief Rolls back read pointer for retransmit.
    void rewindTo(uint32_t seq) noexcept
    {
        if (!initialized_)
            return;
        if (static_cast<int32_t>(seq - seqBase_) < 0)
            return;
        const size_t target = seq - seqBase_;
        if (target >= ackedPos_ && target <= writePos_)
            readPos_ = target;
    }

    // Accessors
    size_t pending() const noexcept
    {
        return writePos_ - readPos_;
    }
    size_t unacked() const noexcept
    {
        return writePos_ - ackedPos_;
    }
    size_t freeSpace() const noexcept
    {
        return capacity_ - (writePos_ - ackedPos_);
    }
    bool initialized() const noexcept
    {
        return initialized_;
    }
    uint32_t seqBase() const noexcept
    {
        return seqBase_;
    }
    uint32_t nextSeq() const noexcept
    {
        return seqBase_ + static_cast<uint32_t>(writePos_);
    }
    uint32_t sndUna() const noexcept
    {
        return seqBase_ + static_cast<uint32_t>(ackedPos_);
    }

    void reset() noexcept
    {
        writePos_ = readPos_ = ackedPos_ = 0;
        initialized_ = false;
        seqBase_ = 0;
    }

private:
    size_t capacity_;
    std::vector<uint8_t> buffer_;
    size_t writePos_;
    size_t readPos_;
    size_t ackedPos_;
    uint32_t seqBase_;
    bool initialized_;
};

} // namespace snet