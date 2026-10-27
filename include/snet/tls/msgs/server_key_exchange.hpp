#pragma once

#include <cstdint>
#include <system_error>

#include <casket/nonstd/span.hpp>
#include <casket/nonstd/variant.hpp>

#include <snet/crypto/group_params.hpp>
#include <snet/crypto/signature_scheme.hpp>

#include <snet/tls/meta_info.hpp>
#include <snet/tls/version.hpp>

#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

class Session;

/// @brief Diffie-Hellman parameters in ServerKeyExchange
///        (TLS 1.0: RFC 2246 §7.4.3; TLS 1.2: RFC 5246 §7.4.3).
///
/// Wire format:
///   `<2-byte length> <prime bytes>`
///   `<2-byte length> <generator bytes>`
///   `<2-byte length> <public value bytes>`.
///
/// All three spans are views into the input buffer passed to `deserialize`;
/// the caller must keep that buffer alive for the lifetime of the object.
struct DhParams final
{
    nonstd::span<const uint8_t> prime{};       ///< DH prime modulus (p); without 2-byte length.
    nonstd::span<const uint8_t> generator{};   ///< DH generator (g); without 2-byte length.
    nonstd::span<const uint8_t> publicValue{}; ///< Server DH public value (g^x mod p); without 2-byte length.

    /// @brief Default constructor; all views are empty.
    DhParams() noexcept = default;

    /// @brief Parses DH parameters from @p reader.
    /// @param[in,out] reader Reader positioned at the first length prefix.
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left with empty views (strong guarantee).
    /// @note `noexcept`. Views point into the reader's buffer.
    std::error_code deserialize(utils::DataReader& reader) noexcept;

    /// @brief Serializes DH parameters into @p output.
    /// @param[in] output Destination buffer.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;
};

/// @brief ECDHE parameters in ServerKeyExchange
///        (TLS 1.0: RFC 4492 §5.4; TLS 1.2: RFC 8422 §5.4).
///
/// Wire format:
///   `<1-byte curve_type>` `<2-byte named_curve>` `<1-byte length> <public point>`.
///
/// Only `named_curve` (curve_type == 3) is supported; explicit curves are
/// rejected.
struct EcdheParams final
{
    std::uint8_t curveType{0};                 ///< Curve type (3 = named_curve).
    crypto::GroupParams curveID{};             ///< Named curve identifier.
    nonstd::span<const uint8_t> publicPoint{}; ///< Server ECDH public point; without 1-byte length.

    /// @brief Default constructor; `curveType == 0`, `publicPoint` empty.
    EcdheParams() noexcept = default;

    /// @brief Parses ECDHE parameters from @p reader.
    /// @param[in,out] reader Reader positioned at the curve type byte.
    /// @return `std::error_code` (`0` on success).
    ///         `LengthOutOfRange` if the curve is not a known pure-ECC group.
    /// @note `noexcept`. `publicPoint` points into the reader's buffer.
    std::error_code deserialize(utils::DataReader& reader) noexcept;

    /// @brief Serializes ECDHE parameters into @p output.
    /// @param[in] output Destination buffer.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output) const noexcept;
};

/// @brief ServerKeyExchange handshake message
///        (TLS 1.0: RFC 2246 §7.4.3; TLS 1.2: RFC 5246 §7.4.3).
///
/// Not used in TLS 1.3 (key exchange is carried in the `key_share`
/// extension). Not used for RSA-only cipher suites.
///
/// Wire format:
///   `<params>` -- one of `DhParams` / `EcdheParams`;
///   `<2-byte scheme>` (TLS 1.2 only) `<2-byte length> <signature>` --
///   signature over the params.
///
/// All spans are views into the input buffer passed to `deserialize`;
/// the caller must keep that buffer alive for the lifetime of the object.
struct ServerKeyExchange final
{
    /// @brief Key exchange parameters; one of `DhParams` / `EcdheParams`.
    using Params = nonstd::variant<DhParams, EcdheParams>;

    Params params{};                         ///< Active key exchange parameters.
    nonstd::span<const uint8_t> data{};      ///< Raw bytes covered by the signature.
    crypto::SignatureScheme scheme{};        ///< Signature scheme (TLS 1.2 only; 0 for < TLS 1.2).
    nonstd::span<const uint8_t> signature{}; ///< Signature; without 2-byte length.

    /// @brief Default constructor; active alternative is `DhParams`.
    ServerKeyExchange() noexcept = default;

    /// @brief Parses the ServerKeyExchange body into `*this`.
    /// @param[in] input    Wire bytes of the ServerKeyExchange body (without
    ///                     the 4-byte handshake header).
    /// @param[in] metaInfo Protocol metadata; `metaInfo.cipherSuite` selects
    ///                     the key exchange algorithm, `metaInfo.version`
    ///                     selects the signature format.
    /// @return `std::error_code` (`0` on success).
    ///         On failure `*this` is left unchanged (strong guarantee).
    /// @note `noexcept`.
    std::error_code deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept;

    /// @brief Serializes the message into @p output.
    /// @param[in] output  Destination buffer.
    /// @param[in] session Session context; `session.getInfo()` provides the
    ///                    cipher suite and protocol version.
    /// @return Bytes written on success, `kSerializationFailed` on error.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept;
};

} // namespace snet::tls