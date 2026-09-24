#pragma once

#include <cstdint>
#include <cstring>
#include <array>
#include <algorithm>
#include <casket/nonstd/span.hpp>

namespace snet::layers
{

/// @brief Builder for TCP options (RFC 793, RFC 2018, RFC 1323, RFC 7323).
///
/// Writes into an internal 40-byte buffer (max TCP options size).
/// User is responsible for aligning to 4 bytes (via nop/eol or manual padding).
class TcpOptions
{
public:
    static constexpr size_t MAX_LEN = 40;

    TcpOptions() = default;

    /// @brief MSS option (kind=2, len=4).
    TcpOptions& mss(uint16_t value) noexcept
    {
        uint8_t opt[4] = {2, 4, static_cast<uint8_t>(value >> 8), static_cast<uint8_t>(value & 0xFF)};
        return append(opt, 4);
    }

    /// @brief SACK Permitted option (kind=4, len=2).
    TcpOptions& sackPermitted() noexcept
    {
        uint8_t opt[2] = {4, 2};
        return append(opt, 2);
    }

    /// @brief Window Scale option (kind=3, len=3).
    TcpOptions& windowScale(uint8_t shift) noexcept
    {
        uint8_t opt[3] = {3, 3, shift};
        return append(opt, 3);
    }

    /// @brief Timestamps option (kind=8, len=10).
    TcpOptions& timestamps(uint32_t tsval, uint32_t tsecr) noexcept
    {
        uint8_t opt[10] = {8,
                           10,
                           static_cast<uint8_t>(tsval >> 24),
                           static_cast<uint8_t>(tsval >> 16),
                           static_cast<uint8_t>(tsval >> 8),
                           static_cast<uint8_t>(tsval),
                           static_cast<uint8_t>(tsecr >> 24),
                           static_cast<uint8_t>(tsecr >> 16),
                           static_cast<uint8_t>(tsecr >> 8),
                           static_cast<uint8_t>(tsecr)};
        return append(opt, 10);
    }

    /// @brief NOP option (kind=1). Used for alignment.
    TcpOptions& nop() noexcept
    {
        uint8_t v = 1;
        return append(&v, 1);
    }

    /// @brief End-of-Options (kind=0).
    TcpOptions& end() noexcept
    {
        uint8_t v = 0;
        return append(&v, 1);
    }

    /// @brief Pad to 4-byte boundary with NOPs.
    TcpOptions& padTo4() noexcept
    {
        while (len_ % 4 != 0)
            nop();
        return *this;
    }

    const uint8_t* data() const noexcept
    {
        return buf_.data();
    }

    size_t size() const noexcept
    {
        return len_;
    }
    bool empty() const noexcept
    {
        return len_ == 0;
    }

    /// @brief doff value for TCP header (in 32-bit words).
    ///        = 5 + (options_size / 4), assuming padded to 4.
    uint8_t doff() const noexcept
    {
        return static_cast<uint8_t>(5 + (len_ + 3) / 4);
    }

private:
    TcpOptions& append(const void* data, size_t len) noexcept
    {
        if (len_ + len > MAX_LEN)
            return *this; // silently drop overflow

        std::memcpy(buf_.data() + len_, data, len);
        len_ += len;
        return *this;
    }

    std::array<uint8_t, MAX_LEN> buf_{};
    size_t len_{0};
};

} // namespace snet::layers