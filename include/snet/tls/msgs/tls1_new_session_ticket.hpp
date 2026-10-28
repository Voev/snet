#pragma once

#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>

namespace snet::tls
{

/// @brief NewSessionTicket handshake message for TLS 1.0 / 1.1 / 1.2
///        (RFC 5077 §3.3).
///
/// Not used in TLS 1.3, which has a different wire format (see
/// `TLSv13NewSessionTicket`).
///
/// Wire format:
///   `<4-byte lifetime_hint>` + `<2-byte ticket length> <ticket bytes>`.
///
/// `ticket` is a view into the input buffer passed to `deserialize`; the
/// caller must keep that buffer alive for the lifetime of the object.
struct TLSv1NewSessionTicket final
{
    /// @brief Ticket lifetime hint in seconds (may be ignored by the client).
    std::uint32_t ticketLifetime{0};

    /// @brief Opaque ticket bytes; 0..65535 entries. Without the 2-byte length prefix.
    nonstd::span<const uint8_t> ticket{};

    /// @brief Default constructor; `ticketLifetime == 0`, `ticket` empty.
    TLSv1NewSessionTicket() noexcept = default;

    /// @brief Parses the NewSessionTicket body into `*this`.
    /// @param[in] input Wire bytes of the NewSessionTicket body (without
    ///                  the 4-byte handshake header).
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left with empty fields (strong guarantee).
    /// @note `noexcept`. `ticket` points into @p input.
    std::error_code deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the message into @p output.
    /// @param[in] output Destination buffer; must hold
    ///                   `4 + 2 + ticket.size()` bytes.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;
};

} // namespace snet::tls