#pragma once

#include <system_error>

#include <casket/nonstd/span.hpp>

#include <snet/tls/version.hpp>
#include <snet/tls/extensions.hpp>
#include <snet/tls/cipher_suite_list.hpp>

namespace snet::tls
{

class Session;

/// @brief TLS ClientHello handshake message (RFC 5246 §7.4.1.2, RFC 8446 §4.1.2).
///
/// All `nonstd::span` fields are views into the input buffer passed to
/// `deserialize`; the caller must keep that buffer alive for the lifetime
/// of the `ClientHello` object.
struct ClientHello final
{
    static constexpr std::size_t kMaxSuites = 128;

    ProtocolVersion version{};                    ///< Client's preferred protocol version (2 bytes on the wire).
    nonstd::span<const uint8_t> random{};         ///< Client random (32 bytes on the wire).
    nonstd::span<const uint8_t> sessionID{};      ///< Session ID; 0..32 bytes (1-byte length on the wire).
    CipherSuiteList<kMaxSuites> suites{};         ///< Cipher suite list.
    nonstd::span<const uint8_t> compMethods{};    ///< Compression methods; 1..255 bytes (1-byte length on the wire).
    nonstd::span<const uint8_t> extensionsData{}; ///< Raw extensions block; empty for SSLv3.0.
    Extensions* extensions{nullptr};              ///< Parsed extensions. Used in serialize.

    /// @brief Default constructor; all fields are empty.
    ClientHello() noexcept = default;

    /// @brief Parses the ClientHello body into `*this`.
    /// @param[in] input Wire bytes of the ClientHello body (without the
    ///                  4-byte handshake header).
    /// @return `std::error_code` (`0` on success).
    ///         On failure, `*this` is left with empty fields (strong guarantee).
    /// @note `noexcept`. Views point into @p input.
    std::error_code deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the message into @p output.
    /// @param[in] output  Destination buffer; must hold at least
    ///                    `2 + random.size() + 1 + sessionID.size() +
    ///                     2 + suites.size() + 1 + compMethods.size()`
    ///                    bytes plus the serialized extensions block.
    ///
    /// @return Bytes written on success, `kSerializationFailed` if @p output
    ///         is too small or extension serialization failed.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;
};

} // namespace snet::tls