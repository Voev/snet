#pragma once

#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>

namespace snet::tls
{

/// @brief TLS 1.3 CertificateRequest handshake message (RFC 8446 §4.3.2).
///
/// Not used in TLS 1.2 (which has a different wire format -- see
/// `TLSv12CertificateRequest`).
///
/// Wire format:
///   `<1-byte length> <certificate_request_context bytes>`   (context; 0..255)
///   `<2-byte length> <extensions block>`                     (Extension extensions<2..2^16-1>)
///
/// Both `nonstd::span` fields are views into the input buffer passed to
/// `deserialize`; the caller must keep that buffer alive for the lifetime
/// of the object.
struct TLSv13CertificateRequest final
{
    /// @brief `certificate_request_context` bytes; 0..255 entries.
    nonstd::span<const uint8_t> certRequestContext{};

    /// @brief Raw extensions block (`<2-byte total length> <ext>*`),
    ///        suitable for `Extensions::deserialize`.
    nonstd::span<const uint8_t> extensionsData{};

    /// @brief Default constructor; both views are empty.
    TLSv13CertificateRequest() noexcept = default;

    /// @brief Parses the CertificateRequest body into `*this`.
    /// @param[in] input Wire bytes of the CertificateRequest body (without
    ///                  the 4-byte handshake header).
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left with empty views (strong guarantee).
    /// @note `noexcept`. Views point into @p input.
    std::error_code deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the message into @p output.
    /// @param[in] output Destination buffer; must hold
    ///                   `1 + certRequestContext.size() + extensionsData.size()` bytes.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`. `extensionsData` is written verbatim (including its
    ///       2-byte total length).
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;
};

} // namespace snet::tls