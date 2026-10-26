#pragma once
#include <casket/nonstd/variant.hpp>

#include <snet/tls/msgs/client_hello.hpp>
#include <snet/tls/msgs/server_hello.hpp>
#include <snet/tls/msgs/encrypted_extensions.hpp>
#include <snet/tls/msgs/client_key_exchange.hpp>
#include <snet/tls/msgs/server_key_exchange.hpp>
#include <snet/tls/msgs/certificate.hpp>
#include <snet/tls/msgs/certificate_request.hpp>
#include <snet/tls/msgs/certificate_verify.hpp>
#include <snet/tls/msgs/finished.hpp>
#include <snet/tls/msgs/new_session_ticket.hpp>
#include <snet/tls/msgs/server_hello_done.hpp>
#include <snet/tls/msgs/key_update.hpp>

namespace snet::tls
{

class Session;

struct HandshakeMessage final
{
    using NoMessage = nonstd::monostate;

    // clang-format off
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
        KeyUpdate
    >;
    // clang-format on

    HandshakeMessage()
        : message(NoMessage())
    {
    }

    explicit HandshakeMessage(MessageType&& msg)
        : message(std::move(msg))
    {
    }

    HandshakeMessage(HandshakeMessage&&) noexcept = default;
    HandshakeMessage& operator=(HandshakeMessage&&) noexcept = default;
    HandshakeMessage(const HandshakeMessage&) = delete;
    HandshakeMessage& operator=(const HandshakeMessage&) = delete;

    /// @todo: make it noexcept.
    static HandshakeMessage deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    /// @todo: make it noexcept.
    size_t serialize(nonstd::span<uint8_t> output, const Session& session);

    template <typename T>
    const T& get() const
    {
        return std::get<T>(message);
    }

    HandshakeType getType() const noexcept;

    MessageType message;
};

} // namespace snet::tls