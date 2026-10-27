#pragma once

#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>

namespace snet::tls
{

class Session;

/// @brief TLS 1.3 EncryptedExtensions handshake message (RFC 8446 §4.3.1).
///
/// Carries the extensions that are protected by the handshake traffic keys
/// (i.e. everything except those in ClientHello/ServerHello). The wire form
/// is exactly the extensions block: `<2-byte total length> <ext>*`.
///
/// The `extensions` field is a view into the input buffer passed to
/// `deserialize`; the caller must keep that buffer alive for the lifetime
/// of the `EncryptedExtensions` object.
struct EncryptedExtensions final
{
    nonstd::span<const uint8_t> extensions{};   ///< Raw extensions block (`<2-byte length> <ext>*`).

    /// @brief Default constructor; `extensions` is empty.
    EncryptedExtensions() noexcept = default;

    /// @brief Parses the EncryptedExtensions body into `*this`.
    /// @param[in] input Wire bytes of the EncryptedExtensions body (without
    ///                  the 4-byte handshake header).
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left with empty fields (strong guarantee).
    /// @note `noexcept`. The view points into @p input.
    std::error_code deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the message into @p output.
    /// @param[in] output  Destination buffer.
    /// @param[in] session Session holding the negotiated extensions.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept;
};

} // namespace snet::tls