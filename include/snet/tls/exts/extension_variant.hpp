#pragma once

#include <cstddef>
#include <type_traits>
#include <variant>

#include <casket/nonstd/span.hpp>

#include <snet/tls/exts/alpn.hpp>
#include <snet/tls/exts/cert_signature_algorithms.hpp>
#include <snet/tls/exts/certificate_type.hpp>
#include <snet/tls/exts/encrypt_then_mac.hpp>
#include <snet/tls/exts/extended_master_secret.hpp>
#include <snet/tls/exts/key_share.hpp>
#include <snet/tls/exts/record_size_limit.hpp>
#include <snet/tls/exts/reneg_extension.hpp>
#include <snet/tls/exts/server_name_indication.hpp>
#include <snet/tls/exts/session_ticket_ext.hpp>
#include <snet/tls/exts/signature_algorithms.hpp>
#include <snet/tls/exts/supported_groups.hpp>
#include <snet/tls/exts/supported_point_formats.hpp>
#include <snet/tls/exts/supported_versions.hpp>
#include <snet/tls/exts/psk_kex_mode.hpp>
#include <snet/tls/exts/extension_code.hpp>
#include <snet/tls/exts/unknown_extension.hpp>

#include <snet/tls/types.hpp>

namespace snet::tls
{

// clang-format off

/// Closed set of all TLS extensions we know how to parse / serialize.
///
/// NOTE: `UnknownExtension` is intentionally **not** an alternative here --
/// its `type()` is a runtime value, not `constexpr staticType()`, so it would
/// break `extensionType(v)` above. Unknown codes are stored separately by
/// `Extensions` in a `std::vector<UnknownExtension>`.
using ExtensionVariant = std::variant<
    ServerNameIndicator,
    SupportedGroups,
    SupportedPointFormats,
    SignatureAlgorithms,
    CertSignatureAlgorithms,
    ALPN,
    ClientCertificateType,
    ServerCertificateType,
    EncryptThenMAC,
    ExtendedMasterSecret,
    RecordSizeLimit,
    SessionTicketExtension,
    SupportedVersions,
    PskKeyExchangeModes,
    KeyShare,
    RenegotiationExtension,
    UnknownExtension
>;

// clang-format on

namespace detail
{

template <typename T>
struct is_unknown_extension : std::is_same<T, UnknownExtension>
{
};

template <typename T, typename = void>
struct has_static_type : std::false_type
{
};

template <typename T>
struct has_static_type<T, std::void_t<decltype(T::staticType())>>
    : std::is_same<decltype(T::staticType()), ExtensionCode>
{
};

template <typename T, typename = void>
struct has_runtime_type : std::false_type
{
};

template <typename T>
struct has_runtime_type<T, std::void_t<decltype(std::declval<const T&>().type())>>
    : std::is_same<decltype(std::declval<const T&>().type()), ExtensionCode>
{
};

template <typename T, typename = void>
struct has_empty : std::false_type
{
};

template <typename T>
struct has_empty<T, std::void_t<decltype(std::declval<const T&>().empty())>>
    : std::is_same<decltype(std::declval<const T&>().empty()), bool>
{
};

template <typename T, typename = void>
struct has_serialize : std::false_type
{
};

template <typename T>
struct has_serialize<T, std::void_t<decltype(std::declval<const T&>().serialize(
                            std::declval<Side>(), std::declval<nonstd::span<uint8_t>>()))>>
    : std::is_same<decltype(std::declval<const T&>().serialize(std::declval<Side>(),
                                                               std::declval<nonstd::span<uint8_t>>())),
                   std::size_t>
{
};

template <typename T, typename = void>
struct has_deserialize_simple : std::false_type
{
};

template <typename T>
struct has_deserialize_simple<T, std::void_t<decltype(std::declval<T&>().deserialize(
                                     std::declval<Side>(), std::declval<nonstd::span<const uint8_t>>()))>>
    : std::is_same<decltype(std::declval<T&>().deserialize(std::declval<Side>(),
                                                           std::declval<nonstd::span<const uint8_t>>())),
                   utils::DecodeError>
{
};

template <typename T, typename = void>
struct has_deserialize_with_handshake : std::false_type
{
};

template <typename T>
struct has_deserialize_with_handshake<
    T, std::void_t<decltype(std::declval<T&>().deserialize(
           std::declval<Side>(), std::declval<nonstd::span<const uint8_t>>(), std::declval<HandshakeType>()))>>
    : std::is_same<decltype(std::declval<T&>().deserialize(
                       std::declval<Side>(), std::declval<nonstd::span<const uint8_t>>(), std::declval<HandshakeType>())),
                   utils::DecodeError>
{
};

/// Basic contract: an extension exposes a code (either `staticType()` or
/// runtime `type()`), `empty()`, and `serialize(Side, span<uint8_t>)`.
/// `UnknownExtension` provides `type()` instead of `staticType()` and is
/// accepted as-is.
template <typename T>
struct is_extension_like_basic : std::bool_constant<(has_static_type<T>::value || has_runtime_type<T>::value) &&
                                                    has_empty<T>::value && has_serialize<T>::value>
{
};

/// Full contract: basic + one of the two `deserialize` shapes.
template <typename T>
struct is_extension_like
    : std::bool_constant<is_extension_like_basic<T>::value &&
                         (has_deserialize_simple<T>::value || has_deserialize_with_handshake<T>::value)>
{
};

template <typename Variant>
struct variant_all_valid : std::false_type
{
};

template <typename... Ts>
struct variant_all_valid<std::variant<Ts...>> : std::bool_constant<(is_extension_like<Ts>::value && ...)>
{
};

} // namespace detail

static_assert(detail::variant_all_valid<ExtensionVariant>::value,
              "ExtensionVariant alternative violates ExtensionLike contract "
              "(missing/incorrect staticType|type/empty/serialize/deserialize)");

/// @brief Gets the wire code of an extension.
inline ExtensionCode extensionType(const ExtensionVariant& v) noexcept
{
    return std::visit(
        [](const auto& e) noexcept -> ExtensionCode
        {
            using T = std::decay_t<decltype(e)>;
            if constexpr (std::is_same_v<T, UnknownExtension>)
            {
                return e.type();
            }
            else
            {
                return e.staticType();
            }
        },
        v);
}

/// @brief Checks whether the active extension is empty (skipped on wire).
inline bool extensionEmpty(const ExtensionVariant& v) noexcept
{
    return std::visit(
        [](const auto& e) noexcept
        {
            return e.empty();
        },
        v);
}

/// @brief Serializes the active extension.
/// @return Bytes written on success, `kSerializationFailed` on error.
inline std::size_t extensionSerialize(const ExtensionVariant& v, Side side, nonstd::span<uint8_t> out) noexcept
{
    return std::visit(
        [side, out](const auto& e) noexcept
        {
            return e.serialize(side, out);
        },
        v);
}

/// @brief Parses the active extension.
///
/// @p handshakeType is needed only by `KeyShare` (its wire format depends on
/// the carrying handshake message); other extensions ignore it. The
/// `if constexpr` branch resolves at compile time per alternative, so
/// `std::visit` still folds into a direct `switch` with no runtime overhead.
inline utils::DecodeError extensionDeserialize(ExtensionVariant& v, Side side, nonstd::span<const uint8_t> in,
                                               HandshakeType ht) noexcept
{
    return std::visit(
        [&](auto& e) noexcept -> utils::DecodeError
        {
            using T = std::decay_t<decltype(e)>;
            if constexpr (std::is_same_v<T, UnknownExtension>)
            {
                return e.deserialize(side, in);
            }
            else if constexpr (std::is_same_v<T, KeyShare>)
            {
                return e.deserialize(side, in, ht);
            }
            else
            {
                return e.deserialize(side, in);
            }
        },
        v);
}

} // namespace snet::tls