#pragma once

#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>

namespace snet::tls
{

/// @brief TLS 1.2 CertificateRequest handshake message (RFC 5246 §7.4.4).
///
/// Not used in TLS 1.3 (which has a different wire format -- see
/// `CertificateRequest`).
///
/// Wire format:
///   `<1-byte length> <certType>*`                          (certificate_types)
///   `<2-byte length> <SignatureAndHashAlgorithm>*`         (supported_signature_algorithms)
///   `<2-byte length> <DistinguishedName>*`                 (certificate_authorities)
///
/// Each `DistinguishedName` is `<2-byte length> <DER bytes>`.
///
/// All `nonstd::span` fields are views into the input buffer passed to
/// `deserialize`; the caller must keep that buffer alive for the lifetime
/// of the object.
struct TLSv12CertificateRequest final
{
    /// @brief `certificate_types` bytes; 1..255 entries (each 1 byte).
    nonstd::span<const uint8_t> certTypes{};

    /// @brief `supported_signature_algorithms` bytes; each entry is a
    ///        2-byte big-endian `SignatureAndHashAlgorithm` code.
    ///        Without the 2-byte length prefix.
    nonstd::span<const uint8_t> supportedSigAlgs{};

    /// @brief `certificate_authorities` list; each entry is
    ///        `<2-byte length> <DER bytes>`. Without the outer 2-byte
    ///        total-length prefix.
    nonstd::span<const uint8_t> certAuthorities{};

    /// @brief Default constructor; all views are empty.
    TLSv12CertificateRequest() noexcept = default;

    /// @brief Parses the CertificateRequest body into `*this`.
    /// @param[in] input Wire bytes of the CertificateRequest body (without
    ///                  the 4-byte handshake header).
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left with empty views (strong guarantee).
    /// @note `noexcept`. Views point into @p input.
    std::error_code deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the message into @p output.
    /// @param[in] output Destination buffer; must hold
    ///                   `1 + certTypes.size() + 2 + supportedSigAlgs.size() +
    ///                    2 + certAuthorities.size()` bytes.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;
};

} // namespace snet::tls