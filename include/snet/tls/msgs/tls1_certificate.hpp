#pragma once

#include <array>
#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>

#include <snet/crypto/typedefs.hpp>

namespace snet::tls
{

/// @brief Certificate handshake message for TLS 1.0 / 1.1 / 1.2
///        (TLS 1.0: RFC 2246 §7.4.2; TLS 1.2: RFC 5246 §7.4.2).
///
/// Not used in TLS 1.3, which has a different wire format (see
/// `TLSv13Certificate`).
///
/// Wire format:
///   `<3-byte total length>` followed by
///   `<3-byte cert length> <DER bytes>` × entryCount.
///
/// `certData` in each entry is a view into the input buffer; the `cert`
/// pointer is filled later by `Session` (e.g. by parsing the DER).
struct TLSv1Certificate final
{
    /// @brief Maximum number of certificates in the chain (implementation limit).
    static constexpr std::size_t kMaxCertChain = 10;

    /// @brief One certificate entry.
    struct Entry final
    {
        /// @brief DER-encoded certificate bytes; view into the input buffer.
        nonstd::span<const uint8_t> certData{};

        /// @brief Parsed certificate; filled by `Session`, may be `nullptr`.
        X509Cert* cert{nullptr};
    };

    /// @brief Parsed certificate entries (valid range is `[0, entryCount)`).
    std::array<Entry, kMaxCertChain> entryList{};

    /// @brief Number of valid entries in `entryList`.
    std::uint8_t entryCount{0};

    /// @brief Default constructor; `entryCount == 0`.
    TLSv1Certificate() noexcept = default;

    /// @brief Parses the Certificate body into `*this`.
    /// @param[in] input Wire bytes of the Certificate body (without the
    ///                  4-byte handshake header).
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left with `entryCount == 0`
    ///         (strong guarantee).
    /// @note `noexcept`. `entryList[i].certData` points into @p input.
    std::error_code deserialize(nonstd::span<const uint8_t> input) noexcept;

    /// @brief Serializes the message into @p output.
    /// @param[in] output Destination buffer; must be large enough.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`. Requires `entryList[i].cert != nullptr` for
    ///       `i < entryCount`; `certData` is ignored (the certificate is
    ///       re-encoded from `cert`).
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;
};

} // namespace snet::tls