#pragma once

#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>
#include <casket/nonstd/variant.hpp>

#include <snet/tls/meta_info.hpp>
#include <snet/tls/msgs/tls1_new_session_ticket.hpp>
#include <snet/tls/msgs/tls13_new_session_ticket.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

class Session;

/// @brief TLS NewSessionTicket handshake message, dispatching on protocol version.
///
/// Holds one of two wire-format variants:
///   * `TLSv1NewSessionTicket`  -- TLS 1.0 / 1.1 / 1.2 (RFC 5077 §3.3);
///   * `TLSv13NewSessionTicket` -- TLS 1.3 (RFC 8446 §4.6.1).
///
/// `deserialize` selects the alternative from `MetaInfo::version`;
/// `serialize` dispatches on the active alternative.
///
/// All view-fields inside the active alternative point into the input buffer
/// passed to `deserialize`; the caller must keep that buffer alive for the
/// lifetime of the `NewSessionTicket` object.
struct NewSessionTicket final
{
    /// @brief Active wire-format variant.
    nonstd::variant<TLSv1NewSessionTicket, TLSv13NewSessionTicket> message;

    /// @brief Default constructor; active alternative is `TLSv1NewSessionTicket`.
    NewSessionTicket() noexcept = default;

    /// @brief Parses the NewSessionTicket body into `*this`.
    /// @param[in] input    Wire bytes of the NewSessionTicket body (without
    ///                     the 4-byte handshake header).
    /// @param[in] metaInfo Protocol metadata; `metaInfo.version` selects the
    ///                     wire format:
    ///                       - `TLSv1_3`           -> `TLSv13NewSessionTicket`;
    ///                       - `TLSv1_0`/`1_1`/`1_2` -> `TLSv1NewSessionTicket`.
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left unchanged (strong guarantee).
    /// @note `noexcept`. Views point into @p input.
    std::error_code deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept;

    /// @brief Serializes the active variant into @p output.
    /// @param[in] output  Destination buffer.
    /// @param[in] session Session context (kept for the uniform
    ///                    `serialize(span, const Session&)` contract; not
    ///                    used by either alternative).
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept;
};

} // namespace snet::tls