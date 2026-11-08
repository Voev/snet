#pragma once

#include <cstdint>
#include <type_traits>

namespace snet::tls
{

/// @brief Named bits of the session state word.
///
/// Stored as a plain `uint64_t` inside `SessionFlags`. Up to 64 independent
/// bits; ordering is stable across versions (do not reorder, only append).
enum class SessionBit : std::uint8_t
{
    // Roles / modes
    IsServer                 = 0,   ///< We are the TLS server (vs client).
    Monitor                  = 1,   ///< Passive observer modes.
    DebugKeys                = 2,   ///< Print derived keys to stdout.

    // Handshake milestones
    ClientHelloSeen          = 3,
    ServerHelloSeen          = 4,
    CertificateSeen          = 5,
    CertificateRequestSeen   = 6,
    CertificateVerifySeen    = 7,
    ServerKeyExchangeSeen    = 8,
    ClientKeyExchangeSeen    = 9,
    FinishedSeen             = 10,
    NewSessionTicketSeen     = 11,
    KeyUpdateSeen            = 12,
    ChangeCipherSpecSeen     = 13,
    HelloRetryRequest        = 14,

    // Negotiated extensions / options
    UseEncryptThenMac        = 15,
    UseExtendedMasterSecret  = 16,
    UseSecureRenegotiation   = 17,
    UseSessionTicket         = 18,
    EarlyDataAccepted        = 19,
    ResumedSession           = 20,

    // Per-side cipher / decrypt state
    ClientCipherActive       = 21,  ///< client write keys installed
    ServerCipherActive       = 22,  ///< server write keys installed
    ClientCanDecrypt         = 23,  ///< client read keys installed
    ServerCanDecrypt         = 24,  ///< server read keys installed

    // Versions
    VersionNegotiated        = 25,
    Tls13Active              = 26,  ///< cached fast-path for version >= 1.3
};

/// @brief Strongly-typed bitset over SessionBit, backed by uint64_t.
///
/// All operations are constexpr and allocation-free. Typical use:
///
///   SessionFlags f;
///   f.set(SessionBit::IsServer);
///   if (f.test(SessionBit::IsServer)) { ... }
class SessionFlags final
{
public:
    constexpr SessionFlags() noexcept = default;

    /// @brief Sets the bit.
    constexpr void set(SessionBit bit) noexcept
    {
        bits_ |= mask(bit);
    }

    /// @brief Sets the bit to the given boolean value.
    constexpr void set(SessionBit bit, bool value) noexcept
    {
        bits_ = value ? (bits_ | mask(bit)) : (bits_ & ~mask(bit));
    }

    /// @brief Clears the bit.
    constexpr void clear(SessionBit bit) noexcept
    {
        bits_ &= ~mask(bit);
    }

    /// @brief Clears all bits.
    constexpr void clearAll() noexcept
    {
        bits_ = 0;
    }

    /// @brief Returns true if the bit is set.
    constexpr bool test(SessionBit bit) const noexcept
    {
        return (bits_ & mask(bit)) != 0;
    }

    /// @brief Atomic-ish test-and-set; returns previous value.
    constexpr bool testAndSet(SessionBit bit) noexcept
    {
        const bool prev = test(bit);
        set(bit);
        return prev;
    }

    /// @brief Atomic-ish test-and-clear; returns previous value.
    constexpr bool testAndClear(SessionBit bit) noexcept
    {
        const bool prev = test(bit);
        clear(bit);
        return prev;
    }

    /// @brief Returns true if all bits in @p mask are set.
    constexpr bool allOf(std::uint64_t mask) const noexcept
    {
        return (bits_ & mask) == mask;
    }

    /// @brief Returns true if any bit in @p mask is set.
    constexpr bool anyOf(std::uint64_t mask) const noexcept
    {
        return (bits_ & mask) != 0;
    }

    /// @brief Raw word access (for serialization / debugging).
    constexpr std::uint64_t raw() const noexcept { return bits_; }
    constexpr void setRaw(std::uint64_t v) noexcept { bits_ = v; }

    /// @brief Number of set bits (useful for diagnostics).
    constexpr unsigned popcount() const noexcept
    {
        std::uint64_t x = bits_;
        unsigned n = 0;
        while (x) { x &= x - 1; ++n; }
        return n;
    }

private:
    static constexpr std::uint64_t mask(SessionBit b) noexcept
    {
        return std::uint64_t{1} << static_cast<std::uint8_t>(b);
    }

    std::uint64_t bits_{0};
};

} // namespace snet::tls