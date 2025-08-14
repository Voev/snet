#include <snet/tls/types.hpp>

namespace snet::tls
{

std::string toString(const RecordType type)
{
    switch (type)
    {
    case RecordType::Handshake:
        return "Handshake";
    case RecordType::ApplicationData:
        return "ApplicationData";
    case RecordType::ChangeCipherSpec:
        return "ChangeCipherSpec";
    case RecordType::Alert:
        return "Alert";
    default:;
    };
    return "None";
}

std::string toString(const HandshakeType type)
{
    switch (type)
    {
    case HandshakeType::HelloRequestCode:
        return "HelloRequest";
    case HandshakeType::ClientHelloCode:
        return "ClientHello";
    case HandshakeType::ServerHelloCode:
        return "ServerHello";
    case HandshakeType::HelloVerifyRequestCode:
        return "HelloVerifyRequest";
    case HandshakeType::NewSessionTicketCode:
        return "NewSessionTicket";
    case HandshakeType::EndOfEarlyDataCode:
        return "EndOfEarlyData";
    case HandshakeType::EncryptedExtensionsCode:
        return "EncryptedExtensions";
    case HandshakeType::CertificateCode:
        return "Certificate";
    case HandshakeType::ServerKeyExchangeCode:
        return "ServerKeyExchange";
    case HandshakeType::CertificateRequestCode:
        return "CertificateRequest";
    case HandshakeType::ServerHelloDoneCode:
        return "ServerHelloDone";
    case HandshakeType::CertificateVerifyCode:
        return "CertificateVerify";
    case HandshakeType::ClientKeyExchangeCode:
        return "ClientKeyExchange";
    case HandshakeType::FinishedCode:
        return "Finished";
    case HandshakeType::KeyUpdateCode:
        return "KeyUpdate";
    case HandshakeType::HelloRetryRequestCode:
        return "HelloRetryRequest";
    case HandshakeType::HandshakeCCSCode:
        return "HandshakeCCS";
    case HandshakeType::NoneCode:
        break;
    };
    return "None";
}

} // namespace snet::tls