#pragma once

#include <cstdint>
#include <system_error>
#include <type_traits>

#include <casket/nonstd/span.hpp>
#include <casket/nonstd/variant.hpp>

#include <snet/tls/meta_info.hpp>

#include <snet/tls/msgs/certificate.hpp>
#include <snet/tls/msgs/certificate_request.hpp>
#include <snet/tls/msgs/certificate_verify.hpp>
#include <snet/tls/msgs/client_hello.hpp>
#include <snet/tls/msgs/client_key_exchange.hpp>
#include <snet/tls/msgs/encrypted_extensions.hpp>
#include <snet/tls/msgs/finished.hpp>
#include <snet/tls/msgs/key_update.hpp>
#include <snet/tls/msgs/new_session_ticket.hpp>
#include <snet/tls/msgs/server_hello.hpp>
#include <snet/tls/msgs/server_hello_done.hpp>
#include <snet/tls/msgs/server_key_exchange.hpp>

namespace snet::tls
{

class Session;

/// @brief TLS handshake message, dispatching on the 1-byte wire type.
///
/// The active alternative is chosen by `deserialize` from the first byte of
/// the handshake header; `serialize` writes the same type byte back.
/// `NoMessage` (i.e. `std::monostate`) is used only as the default-constructed
/// state and for `KeyUpdate`, which has no payload.
///
/// Move-only: several alternatives (`Certificate`, `CertificateRequest`,
/// `KeyShare`-bearing messages) may themselves hold move-only members.
///
/// All view-fields inside the active alternative point into the input buffer
/// passed to `deserialize`; the caller must keep that buffer alive for the
/// lifetime of the `HandshakeMessage`.
class HandshakeMessage final
{
public:
    /// @brief Empty / no-payload alternative (`std::monostate`).
    using NoMessage = nonstd::monostate;

    // clang-format off

    /// @brief Closed set of all supported handshake message types.
    ///
    /// The order MUST match `kIndexToType` in `handshake_message.cpp`:
    /// `getType()` uses the variant index to map back to `HandshakeType`.
    using MessageType = nonstd::variant<
        NoMessage,
        ClientHello,
        ServerHello,
        EncryptedExtensions,
        ServerKeyExchange,
        ClientKeyExchange,
        Certificate,
        CertificateRequest,
        CertificateVerify,
        Finished,
        NewSessionTicket,
        ServerHelloDone,
        KeyUpdate>;

    // clang-format on

    static_assert(std::is_nothrow_move_constructible_v<MessageType>, "MessageType must be nothrow-move-constructible");
    static_assert(std::is_nothrow_move_assignable_v<MessageType>, "MessageType must be nothrow-move-assignable");

    /// @brief Default constructor; active alternative is `NoMessage`.
    HandshakeMessage() noexcept = default;

    /// @brief Constructs from an already-parsed message.
    /// @param[in] msg Parsed message; moved into `message_`.
    explicit HandshakeMessage(MessageType&& msg) noexcept
        : message_(std::move(msg))
    {
    }

    /// @brief Move constructor.
    HandshakeMessage(HandshakeMessage&&) noexcept = default;

    /// @brief Move assignment operator.
    HandshakeMessage& operator=(HandshakeMessage&&) noexcept = default;

    HandshakeMessage(const HandshakeMessage&) = delete;
    HandshakeMessage& operator=(const HandshakeMessage&) = delete;

    /// @brief Parses a handshake message from @p input into @p out.
    /// @param[in] input    Wire bytes (4-byte header + payload).
    /// @param[in] metaInfo Protocol metadata for parsing (version, cipher
    ///                     suite, side); passed to alternatives that need it.
    /// @param[out] out     Parsed message on success; untouched on failure.
    /// @return `std::error_code` (`0` on success). Never throws.
    /// @note On success, view-fields inside @p out point into @p input; the
    ///       caller must keep @p input alive for the lifetime of @p out.
    ///       On failure @p out is unchanged (strong guarantee).
    static std::error_code deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo,
                                       HandshakeMessage& out) noexcept;

    /// @brief Serializes the message into @p output.
    /// @param[in] output  Destination buffer; must hold at least
    ///                    `4 + payload size` bytes.
    /// @param[in] session Session context; forwarded to alternatives that
    ///                    need it (e.g. `ClientHello`/`ServerHello` for
    ///                    extension re-serialization, `CertificateVerify`
    ///                    for `session.side()`).
    /// @return Bytes written on success, `kSerializationFailed` if @p output
    ///         is too small, the active message's serialization failed, or
    ///         the payload exceeds 2^24-1 bytes.
    /// @note `noexcept`.
    std::size_t serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept;

    /// @brief Gets the active message.
    /// @tparam T Concrete type; must be an alternative of `MessageType`.
    /// @return Const reference to the stored alternative.
    /// @throws std::bad_variant_access if @p T is not the active alternative.
    template <typename T>
    const T& get() const
    {
        return std::get<T>(message_);
    }

    /// @brief Gets the wire type of the active message.
    /// @return `HandshakeType` corresponding to the active alternative
    ///         (`HandshakeType::NoneCode` for `NoMessage` or an out-of-range
    ///         index, which should not happen given the `static_assert`).
    /// @note `noexcept`.
    HandshakeType getType() const noexcept;

private:
    MessageType message_; ///< Active message; `NoMessage` if none.
};

} // namespace snet::tls