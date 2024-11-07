#include <snet/tls/types.hpp>

namespace snet::tls
{

std::string toString(const HandshakeType type)
{
    switch (type)
    {
    case HandshakeType::HelloRequest:
        return "HelloRequest";
    case HandshakeType::ClientHello:
        return "ClientHello";
    case HandshakeType::ServerHello:
        return "ServerHello";
    case HandshakeType::HelloVerifyRequest:
        return "HelloVerifyRequest";
    case HandshakeType::NewSessionTicket:
        return "NewSessionTicket";
    case HandshakeType::EndOfEarlyData:
        return "EndOfEarlyData";
    case HandshakeType::EncryptedExtensions:
        return "EncryptedExtensions";
    case HandshakeType::Certificate:
        return "Certificate";
    case HandshakeType::ServerKeyExchange:
        return "ServerKeyExchange";
    case HandshakeType::CertificateRequest:
        return "CertificateRequest";
    case HandshakeType::ServerHelloDone:
        return "ServerHelloDone";
    case HandshakeType::CertificateVerify:
        return "CertificateVerify";
    case HandshakeType::ClientKeyExchange:
        return "ClientKeyExchange";
    case HandshakeType::Finished:
        return "Finished";
    case HandshakeType::KeyUpdate:
        return "KeyUpdate";
    case HandshakeType::HelloRetryRequest:
        return "HelloRetryRequest";
    case HandshakeType::HandshakeCCS:
        return "HandshakeCCS";
    case HandshakeType::None:
        break;
    };
    return "None";
}

} // namespace snet::tls