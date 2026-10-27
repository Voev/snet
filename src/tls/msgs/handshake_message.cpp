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

    utils::DataReader reader(input);

    const auto messageType = static_cast<HandshakeType>(reader.get_byte());
    const auto messageLength = reader.get_uint24_t();
    casket::ThrowIfFalse(reader.remaining_bytes() == messageLength, "Incorrect length of handshake message");

    auto payload = input.subspan(TLS_HANDSHAKE_HEADER_SIZE, messageLength);

    MessageType message;
    std::error_code err{};

    switch (messageType)
    {
    case HandshakeType::ClientHelloCode:
    {
        err = message.emplace<ClientHello>().deserialize(payload);
        break;
    }
    case HandshakeType::ServerHelloCode:
    {
        err = message.emplace<ServerHello>().deserialize(payload);
        break;
    }
    case HandshakeType::EncryptedExtensionsCode:
    {
        err = message.emplace<EncryptedExtensions>().deserialize(payload);
        break;
    }
    case HandshakeType::CertificateCode:
    {
        err = message.emplace<Certificate>().deserialize(payload, metaInfo);
        break;
    }
    case HandshakeType::CertificateRequestCode:
    {
        err = message.emplace<CertificateRequest>().deserialize(payload, metaInfo);
        break;
    }
    case HandshakeType::CertificateVerifyCode:
    {
        err = message.emplace<CertificateVerify>().deserialize(payload, metaInfo);
        break;
    }
    case HandshakeType::ServerKeyExchangeCode:
        message = ServerKeyExchange::deserialize(payload, metaInfo);
        break;
    case HandshakeType::FinishedCode:
    {
        err = message.emplace<Finished>().deserialize(payload);
        break;
    }
    case HandshakeType::ServerHelloDoneCode:
    {
        err = message.emplace<ServerHelloDone>().deserialize(payload);
        break;
    }
    case HandshakeType::KeyUpdateCode:
    {
        err = message.emplace<KeyUpdate>().deserialize(payload);
        break;
    }
    case HandshakeType::ClientKeyExchangeCode:
    {
        err = message.emplace<ClientKeyExchange>().deserialize(payload, metaInfo);
        break;
    }
    case HandshakeType::NewSessionTicketCode:
    {
        err = message.emplace<NewSessionTicket>().deserialize(payload, metaInfo);
        break;
    }
    default:
        throw casket::RuntimeError("Unknown handshake message type");
    }

    if (err)
    {
        throw casket::SystemError(err);
    }

    return HandshakeMessage(std::move(message));
}

size_t HandshakeMessage::serialize(nonstd::span<uint8_t> output, const Session& session) noexcept
{
    const size_t payloadSize = nonstd::visit(
        [&output, &session](auto&& msg) -> size_t
        {
            using T = std::decay_t<decltype(msg)>;
            if constexpr (std::is_same_v<T, nonstd::monostate>)
            {
                return 0;
            }
            else
            {
                auto payload = output.subspan(TLS_HANDSHAKE_HEADER_SIZE);
                return msg.serialize(payload, session);
            }
        },
        message_);

    output[0] = static_cast<uint8_t>(getType());
    auto length = static_cast<uint32_t>(payloadSize);
    output[1] = casket::get_byte<1>(length);
    output[2] = casket::get_byte<2>(length);
    output[3] = casket::get_byte<3>(length);

    return TLS_HANDSHAKE_HEADER_SIZE + payloadSize;
}

inline constexpr HandshakeType kIndexToType[] = {
    HandshakeType::NoneCode,                // 0
    HandshakeType::ClientHelloCode,         // 1
    HandshakeType::ServerHelloCode,         // 2
    HandshakeType::EncryptedExtensionsCode, // 3
    HandshakeType::ServerKeyExchangeCode,   // 4
    HandshakeType::ClientKeyExchangeCode,   // 5
    HandshakeType::CertificateCode,         // 6
    HandshakeType::CertificateRequestCode,  // 7
    HandshakeType::CertificateVerifyCode,   // 8
    HandshakeType::FinishedCode,            // 9
    HandshakeType::NewSessionTicketCode,    // 10
    HandshakeType::ServerHelloDoneCode,     // 11
    HandshakeType::KeyUpdateCode,           // 12
};
static_assert(std::size(kIndexToType) == 13);

HandshakeType HandshakeMessage::getType() const noexcept
{
    const auto idx = message_.index();
    assert(idx < std::size(kIndexToType));
    return kIndexToType[idx];
}

} // namespace snet::tls