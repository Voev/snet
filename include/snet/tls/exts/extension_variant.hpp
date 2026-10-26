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

#include <snet/tls/types.hpp>

namespace snet::tls
{

/// Closed set of all TLS extensions we know how to parse / serialize.
///
/// NOTE: `UnknownExtension` is intentionally **not** an alternative here --
/// its `type()` is a runtime value, not `constexpr staticType()`, so it would
/// break `extensionType(v)` above. Unknown codes are stored separately by
/// `Extensions` in a `std::vector<UnknownExtension>`.
using ExtensionVariant = std::variant<ServerNameIndicator, SupportedGroups, SupportedPointFormats, SignatureAlgorithms,
                                      CertSignatureAlgorithms, ALPN, ClientCertificateType, ServerCertificateType,
                                      EncryptThenMAC, ExtendedMasterSecret, RecordSizeLimit, SessionTicketExtension,
                                      SupportedVersions, PskKeyExchangeModes, KeyShare, RenegotiationExtension>;

// ---- C++17 contract checks (SFINAE, no concepts) -------------------------

namespace detail
{

/// `deserialize(side, in)` -- true for every extension except `KeyShare`.
template <typename T, typename = void>
struct has_deserialize_simple : std::false_type
{
};

template <typename T>
struct has_deserialize_simple<T, std::void_t<decltype(std::declval<T&>().deserialize(
                                     std::declval<Side>(), std::declval<nonstd::span<const uint8_t>>()))>>
    : std::true_type
{
};

/// `deserialize(side, in, ht)` -- true only for `KeyShare`.
template <typename T, typename = void>
struct has_deserialize_with_handshake : std::false_type
{
};

template <typename T>
struct has_deserialize_with_handshake<
    T, std::void_t<decltype(std::declval<T&>().deserialize(
           std::declval<Side>(), std::declval<nonstd::span<const uint8_t>>(), std::declval<HandshakeType>()))>>
    : std::true_type
{
};

/// Basic `ExtensionLike` contract: `staticType`, `empty`, `serialize`.
template <typename T, typename = void>
struct is_extension_like_basic : std::false_type
{
};

template <typename T>
struct is_extension_like_basic<T, std::void_t<decltype(T::staticType()), decltype(std::declval<const T&>().empty()),
                                              decltype(std::declval<const T&>().serialize(
                                                  std::declval<Side>(), std::declval<nonstd::span<uint8_t>>()))>>
    : std::bool_constant<std::is_same_v<decltype(T::staticType()), ExtensionCode> &&
                         std::is_same_v<decltype(std::declval<const T&>().empty()), bool> &&
                         std::is_same_v<decltype(std::declval<const T&>().serialize(
                                            std::declval<Side>(), std::declval<nonstd::span<uint8_t>>())),
                                        std::size_t>>
{
};

/// Full `ExtensionLike`: basic + one of the two `deserialize` shapes.
template <typename T>
struct is_extension_like
    : std::bool_constant<is_extension_like_basic<T>::value &&
                         (has_deserialize_simple<T>::value || has_deserialize_with_handshake<T>::value)>
{
};

/// All alternatives of a `std::variant` satisfy `is_extension_like`.
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
              "(missing/incorrect staticType/empty/serialize/deserialize)");

// ---- dispatch (std::visit -> static switch, no vtable, no RTTI) ----------

/// @brief Gets the wire code of an extension.
inline ExtensionCode extensionType(const ExtensionVariant& v) noexcept
{
    return std::visit(
        [](const auto& e) noexcept
        {
            return e.staticType();
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
                                               HandshakeType handshakeType) noexcept
{
    return std::visit(
        [&](auto& e) noexcept -> utils::DecodeError
        {
            using T = std::decay_t<decltype(e)>;
            if constexpr (detail::has_deserialize_with_handshake<T>::value)
            {
                return e.deserialize(side, in, handshakeType); // KeyShare
            }
            else
            {
                (void)handshakeType;
                return e.deserialize(side, in); // everything else
            }
        },
        v);
}

} // namespace snet::tls