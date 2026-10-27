#pragma once

#include <cstdint>
#include <cstring>
#include <system_error>

#include <casket/nonstd/span.hpp>

namespace snet::tls
{

class Session;

/// @brief TLS Finished handshake message (TLS 1.2: RFC 5246 §7.4.9;
///        TLS 1.3: RFC 8446 §4.4.4).
///
/// Carries `verify_data` - the result of a MAC (TLS 1.2 PRF or TLS 1.3 HMAC)
/// over the handshake transcript, optionally followed by a MAC over the
/// master secret (TLS 1.2 only).
///
/// Length depends on the negotiated cipher suite's hash:
///   * TLS 1.2: 12 bytes (`verify_data` from PRF) + MAC length (e.g. 20 for
///     SHA-1, 32 for SHA-256, 48 for SHA-384);
///   * TLS 1.3: 32 bytes for SHA-256, 48 bytes for SHA-384.
///
/// The `verifyData` field is a view into the input buffer passed to
/// `deserialize`; the caller must keep that buffer alive for the lifetime
/// of the `Finished` object.
struct Finished final
{
    nonstd::span<const uint8_t> verifyData{}; ///< `verify_data` bytes; length depends on hash.

    /// @brief Default constructor; `verifyData` is empty.
    Finished() noexcept = default;

    /// @brief Parses the Finished body into `*this`.
    /// @param[in] input Wire bytes of the Finished body (the whole payload
    ///                  is `verify_data`; no header).
    /// @return `std::error_code` (`0` on success).
    /// @note `noexcept`. The view points into @p input.
    ///       No length validation is performed here; the caller
    ///       (Session) must check the length against the negotiated hash.
    std::error_code deserialize(nonstd::span<const uint8_t> input) noexcept
    {
        verifyData = input;
        return {};
    }

    /// @brief Serializes the message into @p output.
    /// @param[in] output  Destination buffer; must hold `verifyData.size()` bytes.
    /// @param[in] session Unused; kept for the uniform `serialize(span, const Session&)` contract.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept
    {
        (void)session;

        if (output.size_bytes() < verifyData.size())
        {
            return kSerializationFailed;
        }

        if (!verifyData.empty())
        {
            std::memcpy(output.data(), verifyData.data(), verifyData.size());
        }
        return verifyData.size();
    }
};

} // namespace snet::tls