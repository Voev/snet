#pragma once

#include <array>
#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>

#include <snet/tls/version.hpp>

namespace snet::tls
{

class Session;

/// @brief TLS ServerHello handshake message (RFC 5246 §7.4.1.3, RFC 8446 §4.1.3).
///
/// Also represents a TLS 1.3 HelloRetryRequest: it has the same structure,
/// with `random` set to the special HRR marker. Use `isHelloRetryRequest`
/// to distinguish.
///
/// All `nonstd::span` fields are views into the input buffer passed to
/// `deserialize`; the caller must keep that buffer alive for the lifetime
/// of the `ServerHello` object.
struct ServerHello final
{
    ProtocolVersion version{};                ///< Negotiated protocol version (2 bytes on the wire).
    nonstd::span<const uint8_t> random{};     ///< Server random (32 bytes on the wire).
    nonstd::span<const uint8_t> sessionID{};  ///< Session ID; 0..32 bytes (1-byte length on the wire).
    uint16_t cipherSuite{0};                  ///< Selected cipher suite code (big-endian on the wire).
    uint8_t compMethod{0};                    ///< Selected compression method.
    nonstd::span<const uint8_t> extensions{}; ///< Raw extensions block; empty if absent.
    bool isHelloRetryRequest{false};          ///< `true` if `random` matches the HRR marker.

    /// @brief Default constructor; all fields are empty.
    ServerHello() noexcept = default;

    /// @brief Parses the ServerHello body into `*this`.
    /// @param[in] input Wire bytes of the ServerHello body (without the
    ///                  4-byte handshake header).
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left with empty fields (strong guarantee).
    /// @note `noexcept`. Views point into @p input.
    std::error_code deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the message into @p output.
    /// @param[in] output  Destination buffer.
    /// @param[in] session Session holding the negotiated extensions.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept;
};

} // namespace snet::tls