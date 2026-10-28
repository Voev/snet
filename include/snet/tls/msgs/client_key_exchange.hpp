#pragma once

#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>
#include <casket/nonstd/variant.hpp>

#include <snet/tls/meta_info.hpp>
#include <snet/tls/version.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/decode_error.hpp>

namespace snet::tls
{

class Session;

/// @brief Encrypted pre-master secret for RSA key exchange
///        (TLS 1.0: RFC 2246 §7.4.7.1; TLS 1.2: RFC 5246 §7.4.7.1).
///
/// Wire format: `<2-byte length> <encrypted PMS bytes>`.
///
/// `preMasterSecret` is a view into the input buffer passed to
/// `deserialize` (or the reader's buffer); the caller must keep that
/// buffer alive for the lifetime of the object.
struct EncryptedPreMasterSecret final
{
    /// @brief Encrypted pre-master secret bytes; without the 2-byte length prefix.
    nonstd::span<const uint8_t> preMasterSecret{};

    /// @brief Default constructor; `preMasterSecret` is empty.
    EncryptedPreMasterSecret() noexcept = default;

    /// @brief Parses the encrypted pre-master secret from @p reader.
    /// @param[in,out] reader Reader positioned at the encrypted PMS.
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left with an empty view (strong guarantee).
    /// @note `noexcept`. The view points into the reader's buffer.
    std::error_code deserialize(utils::DataReader& reader) noexcept;

    /// @brief Serializes the encrypted pre-master secret into @p output.
    /// @param[in] output Destination buffer; must hold
    ///                   `2 + preMasterSecret.size()` bytes.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;
};

/// @brief Client DH public value for DHE key exchange
///        (TLS 1.0: RFC 2246 §7.4.7.2; TLS 1.2: RFC 5246 §7.4.7.2).
///
/// Wire format: `<2-byte length> <dh_Yc bytes>`.
///
/// `dhPublic` is a view into the input buffer passed to `deserialize`;
/// the caller must keep that buffer alive for the lifetime of the object.
struct ClientDhPublic final
{
    /// @brief DH public value bytes; without the 2-byte length prefix.
    nonstd::span<const uint8_t> dhPublic{};

    /// @brief Default constructor; `dhPublic` is empty.
    ClientDhPublic() noexcept = default;

    /// @brief Parses the DH public value from @p reader.
    /// @param[in,out] reader Reader positioned at the DH public value.
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left with an empty view (strong guarantee).
    /// @note `noexcept`. The view points into the reader's buffer.
    std::error_code deserialize(utils::DataReader& reader) noexcept;

    /// @brief Serializes the DH public value into @p output.
    /// @param[in] output Destination buffer; must hold
    ///                   `2 + dhPublic.size()` bytes.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;
};

/// @brief Client ECDH public value for ECDHE key exchange
///        (TLS 1.0: RFC 4492 §5.7; TLS 1.2: RFC 8422 §5.7).
///
/// Wire format: `<1-byte length> <ecdh_Yc bytes>`.
///
/// `ecdhPublic` is a view into the input buffer passed to `deserialize`;
/// the caller must keep that buffer alive for the lifetime of the object.
struct ClientEcdhPublic final
{
    /// @brief ECDH public value bytes; without the 1-byte length prefix.
    nonstd::span<const uint8_t> ecdhPublic{};

    /// @brief Default constructor; `ecdhPublic` is empty.
    ClientEcdhPublic() noexcept = default;

    /// @brief Parses the ECDH public value from @p reader.
    /// @param[in,out] reader Reader positioned at the ECDH public value.
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left with an empty view (strong guarantee).
    /// @note `noexcept`. The view points into the reader's buffer.
    std::error_code deserialize(utils::DataReader& reader) noexcept;

    /// @brief Serializes the ECDH public value into @p output.
    /// @param[in] output Destination buffer; must hold
    ///                   `1 + ecdhPublic.size()` bytes.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;
};

/// @brief ClientKeyExchange handshake message (TLS 1.0–1.2;
///        TLS 1.0: RFC 2246 §7.4.7; TLS 1.2: RFC 5246 §7.4.7).
///
/// The active alternative is selected by the key exchange algorithm
/// derived from `MetaInfo::cipherSuite`:
///   * `NID_kx_rsa`             -> `EncryptedPreMasterSecret`;
///   * `NID_kx_dhe` / `_dhe_psk`  -> `ClientDhPublic`;
///   * `NID_kx_ecdhe` / `_ecdhe_psk` -> `ClientEcdhPublic`.
///
/// Not used in TLS 1.3, where the key exchange is carried in the `key_share`
/// extension of `ClientHello` / `ServerHello`.
struct ClientKeyExchange final
{
    /// @brief Key exchange parameters; one of three wire-format variants.
    using Params = nonstd::variant<EncryptedPreMasterSecret, ClientDhPublic, ClientEcdhPublic>;

    /// @brief Active key exchange parameters; set by `deserialize`.
    Params params{};

    /// @brief Default constructor; active alternative is `EncryptedPreMasterSecret`.
    ClientKeyExchange() noexcept = default;

    /// @brief Parses the ClientKeyExchange body into `*this`.
    /// @param[in] input    Wire bytes of the ClientKeyExchange body (without
    ///                     the 4-byte handshake header).
    /// @param[in] metaInfo Protocol metadata; `metaInfo.cipherSuite` selects
    ///                     the key exchange algorithm.
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left unchanged (strong guarantee).
    /// @note `noexcept`. Views point into @p input.
    std::error_code deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept;

    /// @brief Serializes the active alternative into @p output.
    /// @param[in] output  Destination buffer.
    /// @param[in] session Session context (unused; kept for the uniform
    ///                    `serialize(span, const Session&)` contract).
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept;
};

} // namespace snet::tls