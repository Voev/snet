#include <cassert>
#include <snet/tls/msgs/handshake_message.hpp>
#include <snet/tls/session.hpp>

namespace snet::tls
{

HandshakeMessage HandshakeMessage::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    if (input.size() < TLS_HANDSHAKE_HEADER_SIZE)
    {
        throw std::runtime_error("Input buffer too small for handshake header");
    }

    utils::DataReader reader("Handshake Message", input);

    const auto messageType = static_cast<HandshakeType>(reader.get_byte());
    const auto messageLength = reader.get_uint24_t();
    casket::ThrowIfFalse(reader.remaining_bytes() == messageLength, "Incorrect length of handshake message");
    
    auto payload = input.subspan(TLS_HANDSHAKE_HEADER_SIZE, messageLength);
    
    MessageType message;
    switch (messageType)
    {
    case HandshakeType::ClientHelloCode:
        message = ClientHello::deserialize(payload);
        break;
    case HandshakeType::ServerHelloCode:
        message = ServerHello::deserialize(payload);
        break;
    case HandshakeType::EncryptedExtensionsCode:
        message = EncryptedExtensions::deserialize(payload);
        break;
    case HandshakeType::CertificateCode:
        message = Certificate::deserialize(payload, metaInfo);
        break;
    case HandshakeType::CertificateVerifyCode:
        message = CertificateVerify::deserialize(payload);
        break;
    case HandshakeType::ServerKeyExchangeCode:
        message = ServerKeyExchange::deserialize(payload, metaInfo);
        break;
    case HandshakeType::FinishedCode:
        message = Finished::deserialize(payload);
        break;
    case HandshakeType::ServerHelloDoneCode:
        // Nothing to do?
        break;
    case HandshakeType::KeyUpdateCode:
        // Nothing to do?
        break;
    case HandshakeType::ClientKeyExchangeCode:
        /// @todo: support it.
        break;
    case HandshakeType::NewSessionTicketCode:
        /// @todo: support it.
        break;
    default:
        throw casket::RuntimeError("Unknown handshake message type");
    }

    return HandshakeMessage(std::move(message), messageType);
}

size_t HandshakeMessage::serialize(nonstd::span<uint8_t> output, const Session& session)
{
    const size_t payloadSize = std::visit(
        [&output, &session](auto&& msg) -> size_t
        {
            auto payload = output.subspan(TLS_HANDSHAKE_HEADER_SIZE);
            return msg.serialize(payload, session);
        },
        message);

    output[0] = static_cast<uint8_t>(type);
    auto length = static_cast<uint32_t>(payloadSize);
    output[1] = casket::get_byte<0>(length);
    output[2] = casket::get_byte<1>(length);
    output[3] = casket::get_byte<2>(length);

    return TLS_HANDSHAKE_HEADER_SIZE + payloadSize;
}

} // namespace snet::tls