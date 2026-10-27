#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <system_error>

#include <casket/nonstd/span.hpp>

#include <snet/crypto/typedefs.hpp>
#include <snet/tls/extensions.hpp>

namespace snet::tls
{

class Session;

/// @brief Certificate handshake message for TLS 1.3 (RFC 8446 §4.4.2).
///
/// Wire format:
///   `<1-byte context length> <certificate_request_context bytes>`   (0..255)
///   `<3-byte total length>` followed by
///   `<3-byte cert length> <DER bytes> <2-byte ext length> <ext>*` × entryCount.
///
/// `certData` and `extsData` in each entry are views into the input buffer.
/// `extensions` is populated by `Session` after `deserialize` (optional);
/// if present, `serialize` re-serializes it instead of copying `extsData`.
struct TLSv13Certificate final
{
    static constexpr std::size_t kMaxCertChain = 10;

    struct Entry final
    {
        nonstd::span<const uint8_t> certData{}; ///< DER-encoded certificate; view into input.
        nonstd::span<const uint8_t> extsData{}; ///< Raw extensions block; view into input.
        X509Cert* cert{nullptr};                ///< Parsed certificate; filled by Session.
        Extensions* extensions{nullptr};        ///< Parsed extensions; filled by Session (optional).
    };

    nonstd::span<const uint8_t> requestContext{}; ///< `certificate_request_context` bytes (0..255).
    std::array<Entry, kMaxCertChain> entryList{}; ///< Certificate entries.
    std::uint8_t entryCount{0};                   ///< Number of valid entries.

    TLSv13Certificate() noexcept = default;

    // move-only (Extensions is move-only)
    TLSv13Certificate(TLSv13Certificate&&) noexcept = default;
    TLSv13Certificate& operator=(TLSv13Certificate&&) noexcept = default;
    TLSv13Certificate(const TLSv13Certificate&) = delete;
    TLSv13Certificate& operator=(const TLSv13Certificate&) = delete;

    std::error_code deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the message into @p output.
    /// @param[in] output Destination buffer.
    /// @param[in] session Session context; `session.side()` is used when an
    ///                    entry has parsed `extensions` that need re-serialization.
    std::size_t serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept;
};

} // namespace snet::tls