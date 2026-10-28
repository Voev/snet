#pragma once

#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>
#include <casket/nonstd/variant.hpp>

#include <snet/tls/meta_info.hpp>
#include <snet/tls/msgs/tls1_certificate.hpp>
#include <snet/tls/msgs/tls13_certificate.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

class Session;

/// @brief TLS Certificate handshake message, dispatching on protocol version.
///
/// Holds one of two wire-format variants:
///   * `TLSv1Certificate`  -- TLS 1.0 / 1.1 / 1.2 (RFC 5246 §7.4.2);
///   * `TLSv13Certificate` -- TLS 1.3 (RFC 8446 §4.4.2).
///
/// `deserialize` selects the alternative from `MetaInfo::version`;
/// `serialize` dispatches on the active alternative and passes `Session`
/// through (used by `TLSv13Certificate` for `session.side()`).
///
/// Move-only: `TLSv13Certificate` may hold `std::optional<Extensions>`,
/// which is move-only.
struct Certificate final
{
    /// @brief Active wire-format variant.
    nonstd::variant<TLSv1Certificate, TLSv13Certificate> message;

    /// @brief Default constructor; active alternative is `TLSv1Certificate`.
    Certificate() noexcept = default;

    Certificate(Certificate&&) noexcept = default;
    Certificate& operator=(Certificate&&) noexcept = default;
    Certificate(const Certificate&) = delete;
    Certificate& operator=(const Certificate&) = delete;

    /// @brief Parses the Certificate body into `*this`.
    /// @param[in] input    Wire bytes of the Certificate body (without the
    ///                     4-byte handshake header).
    /// @param[in] metaInfo Protocol metadata; `metaInfo.version` selects the
    ///                     wire format:
    ///                       - `TLSv1_3`              -> `TLSv13Certificate`;
    ///                       - `TLSv1_0`/`1_1`/`1_2`  -> `TLSv1Certificate`.
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left unchanged (strong guarantee).
    /// @note `noexcept`. Views point into @p input.
    std::error_code deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept;

    /// @brief Serializes the active variant into @p output.
    /// @param[in] output  Destination buffer.
    /// @param[in] session Session context; `TLSv13Certificate` uses
    ///                    `session.side()` for extension re-serialization.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept;
};

} // namespace snet::tls