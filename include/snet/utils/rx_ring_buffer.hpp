#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>

namespace snet
{

/// @brief Transport receive ring buffer with out-of-order write support.
///
/// Inspired by Linux TCP's sk_rcvbuf: data is written at absolute sequence
/// positions, holes are tracked via a bitmap. Consumer reads contiguously
/// from the "consumed" position.
///
/// Layout:
///   seq_base ... seq_base + capacity (wraps by modulo)
///   - write:  writeAt(seq, data, len)
///   - read:   read(out, maxLen)  /  peek()  /  consume(n)
///   - state:  contiguousSeq() — first byte available to consumer
class RxRingBuffer
{
public:
    static constexpr size_t DEFAULT_CAPACITY = 64 * 1024;
    static constexpr size_t MAX_CAPACITY = 1 * 1024 * 1024; // hard limit

    explicit RxRingBuffer(size_t capacity = DEFAULT_CAPACITY)
        : capacity_(std::min(capacity, MAX_CAPACITY))
        , buffer_(capacity_)
        , bitmap_((capacity_ + 63) / 64, 0)
        , seqBase_(0)
        , writeSeq_(0)
        , contiguousSeq_(0)
        , consumedSeq_(0)
        , initialized_(false)
    {
    }

    /// @brief Initializes the stream at a given absolute sequence.
    /// Called on the first segment of the stream.
    void initAt(uint32_t seq) noexcept
    {
        seqBase_ = seq;
        writeSeq_ = seq;
        contiguousSeq_ = seq;
        consumedSeq_ = seq;
        initialized_ = true;
        std::fill(bitmap_.begin(), bitmap_.end(), 0);
    }

    /// @brief Writes data at an absolute sequence position.
    ///
    /// Handles out-of-order arrivals: data is placed at the correct
    /// offset inside the ring, holes are marked in the bitmap.
    ///
    /// @return Number of bytes actually written (may be < len on overflow).
    size_t writeAt(uint32_t seq, const uint8_t* data, size_t len) noexcept
    {
        if (!initialized_ || len == 0)
            return 0;

        // Reject data that is too far behind or ahead
        const int32_t behind = static_cast<int32_t>(seq - consumedSeq_);
        if (behind < 0)
        {
            // Fully retransmitted / already consumed — trim front
            const size_t skip = static_cast<size_t>(-behind);
            if (skip >= len)
                return 0; // fully duplicate
            seq += skip;
            data += skip;
            len -= skip;
        }

        const int32_t ahead = static_cast<int32_t>(seq - consumedSeq_);
        if (ahead >= static_cast<int32_t>(capacity_))
        {
            // Would overflow ring — truncate
            const size_t overflow = static_cast<size_t>(ahead) - capacity_ + 1;
            if (overflow >= len)
                return 0;
            len -= overflow;
        }

        // Clamp to ring capacity
        if (len > capacity_)
            len = capacity_;

        // Write into ring (may wrap)
        size_t offset = ringOffset(seq);
        size_t firstChunk = std::min(len, capacity_ - offset);
        std::memcpy(buffer_.data() + offset, data, firstChunk);
        if (firstChunk < len)
        {
            std::memcpy(buffer_.data(), data + firstChunk, len - firstChunk);
        }

        // Mark bitmap
        markBitmap(seq, len);

        // Track highest written sequence
        const uint32_t endSeq = seq + static_cast<uint32_t>(len);
        if (static_cast<int32_t>(endSeq - writeSeq_) > 0)
            writeSeq_ = endSeq;

        return len;
    }

    /// @brief Advances the contiguous pointer as far as bitmap allows.
    ///
    /// Call after every writeAt. Moves contiguousSeq_ forward while
    /// fully-written regions are available.
    void advanceContiguous() noexcept
    {
        if (!initialized_)
            return;

        while (static_cast<int32_t>(contiguousSeq_ - writeSeq_) < 0)
        {
            // Check how many contiguous bytes are available from contiguousSeq_
            // Find the end of the current written run.
            const size_t chunk = contiguousBytesAt(contiguousSeq_);
            if (chunk == 0)
                break; // hole — stop

            contiguousSeq_ += static_cast<uint32_t>(chunk);
        }
    }

    /// @brief Returns bytes available for reading (contiguous).
    size_t available() const noexcept
    {
        return static_cast<size_t>(contiguousSeq_ - consumedSeq_);
    }

    /// @brief Returns a contiguous view of readable data (zero-copy peek).
    ///
    /// The returned span is valid until the next writeAt/consume call.
    /// May be shorter than available() if the ring wraps.
    std::pair<const uint8_t*, size_t> peek() const noexcept
    {
        const size_t avail = available();
        if (avail == 0)
            return {nullptr, 0};

        const size_t offset = ringOffset(consumedSeq_);
        const size_t firstChunk = std::min(avail, capacity_ - offset);
        return {buffer_.data() + offset, firstChunk};
    }

    /// @brief Reads data into an external buffer (copies).
    /// @return Bytes actually read.
    size_t read(uint8_t* out, size_t maxLen) noexcept
    {
        const size_t avail = available();
        const size_t toRead = std::min(maxLen, avail);
        if (toRead == 0)
            return 0;

        const size_t offset = ringOffset(consumedSeq_);
        const size_t firstChunk = std::min(toRead, capacity_ - offset);

        std::memcpy(out, buffer_.data() + offset, firstChunk);
        if (firstChunk < toRead)
        {
            std::memcpy(out + firstChunk, buffer_.data(), toRead - firstChunk);
        }

        clearBitmap(consumedSeq_, toRead);
        consumedSeq_ += static_cast<uint32_t>(toRead);
        return toRead;
    }

    /// @brief Consumes n bytes after a peek (zero-copy path).
    void consume(size_t n) noexcept
    {
        const size_t avail = available();
        n = std::min(n, avail);
        if (n == 0)
            return;

        clearBitmap(consumedSeq_, n);
        consumedSeq_ += static_cast<uint32_t>(n);
    }

    /// @brief Resets the ring to an uninitialized state.
    void reset() noexcept
    {
        initialized_ = false;
        seqBase_ = 0;
        writeSeq_ = 0;
        contiguousSeq_ = 0;
        consumedSeq_ = 0;
        std::fill(bitmap_.begin(), bitmap_.end(), 0);
    }

    bool initialized() const noexcept
    {
        return initialized_;
    }
    size_t capacity() const noexcept
    {
        return capacity_;
    }
    uint32_t contiguousSeq() const noexcept
    {
        return contiguousSeq_;
    }
    uint32_t consumedSeq() const noexcept
    {
        return consumedSeq_;
    }
    uint32_t writeSeq() const noexcept
    {
        return writeSeq_;
    }

    /// @brief Returns true if there is a hole between consumed and write.
    bool hasHole() const noexcept
    {
        return static_cast<int32_t>(writeSeq_ - contiguousSeq_) > 0;
    }

    /// @brief Total bytes missing in the current hole.
    size_t holeSize() const noexcept
    {
        if (!hasHole())
            return 0;
        return static_cast<size_t>(writeSeq_ - contiguousSeq_);
    }

private:

    size_t ringOffset(uint32_t seq) const noexcept
    {
        return (seq - seqBase_) % capacity_;
    }

    // --- Bitmap helpers ---
    // Bit i represents byte at absolute seq (contiguousSeqBase + i).
    // Bitmap wraps around the ring capacity.

    void markBitmap(uint32_t seq, size_t len) noexcept
    {
        for (size_t i = 0; i < len; ++i)
        {
            const size_t off = ringOffset(seq + static_cast<uint32_t>(i));
            bitmap_[off >> 6] |= (uint64_t{1} << (off & 63));
        }
    }

    void clearBitmap(uint32_t seq, size_t len) noexcept
    {
        for (size_t i = 0; i < len; ++i)
        {
            const size_t off = ringOffset(seq + static_cast<uint32_t>(i));
            bitmap_[off >> 6] &= ~(uint64_t{1} << (off & 63));
        }
    }

    /// @brief Returns how many contiguous written bytes start at seq.
    /// Scans the bitmap forward until it finds an unset bit.
    size_t contiguousBytesAt(uint32_t seq) const noexcept
    {
        size_t count = 0;
        while (count < capacity_) {
            // reached writeSeq_?
            if (static_cast<int32_t>(seq + count - writeSeq_) >= 0)
                break; 
            const size_t off = ringOffset(seq + static_cast<uint32_t>(count));
            const bool set = (bitmap_[off >> 6] & (uint64_t{1} << (off & 63))) != 0;
            if (!set)
                break;
            ++count;
        }
        return count;
    }

private:
    size_t capacity_;
    std::vector<uint8_t> buffer_;
    std::vector<uint64_t> bitmap_; // one bit per byte in ring

    uint32_t seqBase_;       // absolute seq of ring[0]
    uint32_t writeSeq_;      // highest written seq
    uint32_t contiguousSeq_; // first byte readable by consumer
    uint32_t consumedSeq_;   // first byte not yet consumed
    bool initialized_;
};

} // namespace snet