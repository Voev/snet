#pragma once

#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>

namespace snet::tls
{

/// @brief NewSessionTicket handshake message for TLS 1.3 (RFC 8446 §4.6.1).
///
/// Not used in TLS 1.0/1.1/1.2 (which have a different wire format -- see
/// `TLSv1NewSessionTicket`).
///
/// Wire format:
///   `<4-byte ticket_lifetime>`
///   `<4-byte ticket_age_add>`
///   `<1-byte nonce length> <ticket_nonce bytes>`          (0..255)
///   `<2-byte ticket length> <ticket bytes>`               (1..65535)
///   `<2-byte extensions length> <extensions block>`       (0..65534)
///
/// All `nonstd::span` fields are views into the input buffer passed to
/// `deserialize`; the caller must keep that buffer alive for the lifetime
/// of the object.
struct TLSv13NewSessionTicket final
{
    /// @brief Ticket lifetime hint in seconds.
    std::uint32_t ticketLifetime{0};

    /// @brief Additive value used to obscure the ticket age.
    std::uint32_t ticketAgeAdd{0};

    /// @brief Ticket nonce; 0..255 bytes. Without the 1-byte length prefix.
    nonstd::span<const uint8_t> ticketNonce{};

    /// @brief Opaque ticket bytes; 1..65535. Without the 2-byte length prefix.
    nonstd::span<const uint8_t> ticket{};

    /// @brief Raw extensions block (`<2-byte total length> <ext>*`), suitable
    ///        for `Extensions::deserialize`. Empty if no extensions.
    nonstd::span<const uint8_t> extsData{};

    /// @brief Default constructor; all fields are zero/empty.
    TLSv13NewSessionTicket() noexcept = default;

    /// @brief Parses the NewSessionTicket body into `*this`.
    /// @param[in] input Wire bytes of the NewSessionTicket body (without
    ///                  the 4-byte handshake header).
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left with empty fields (strong guarantee).
    /// @note `noexcept`. Views point into @p input.
    std::error_code deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the message into @p output.
    /// @param[in] output Destination buffer; must hold
    ///                   `4 + 4 + 1 + ticketNonce.size() + 2 + ticket.size() +
    ///                    extsData.size()` bytes.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`. `extsData` is written verbatim (including its
    ///       2-byte total length).
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;
};

} // namespace snet::tls