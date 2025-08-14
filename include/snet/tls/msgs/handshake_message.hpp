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

    HandshakeMessage()
        : message(ClientHello())
        , type(HandshakeType::NoneCode)
    {}

    static HandshakeMessage deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    size_t serialize(nonstd::span<uint8_t> output, const Session& session);

    HandshakeType getType() const;

    MessageType message;
    HandshakeType type;

private:
    explicit HandshakeMessage(MessageType&& msg, HandshakeType htype)
        : message(std::move(msg))
        , type(htype)
    {
    }

};

} // namespace snet::tls