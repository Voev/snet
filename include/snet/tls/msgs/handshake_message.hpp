#pragma once
#include <variant>

#include <snet/tls/msgs/client_hello.hpp>
#include <snet/tls/msgs/server_hello.hpp>
#include <snet/tls/msgs/encrypted_extensions.hpp>
#include <snet/tls/msgs/server_key_exchange.hpp>
#include <snet/tls/msgs/certificate.hpp>
#include <snet/tls/msgs/certificate_verify.hpp>
#include <snet/tls/msgs/finished.hpp>

namespace snet::tls
{

class Session;

struct HandshakeMessage final
{
    using MessageType = std::variant<ClientHello, ServerHello, EncryptedExtensions, ServerKeyExchange, Certificate,
                                     CertificateVerify, Finished>;

    static HandshakeMessage deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    static size_t serialize(nonstd::span<uint8_t> output, const MessageType& message, const Session& session);

    MessageType message;

private:
    explicit HandshakeMessage(MessageType&& msg)
        : message(std::move(msg))
    {
    }

};

} // namespace snet::tls