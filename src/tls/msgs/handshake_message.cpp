#include <cassert>
#include <snet/tls/msgs/handshake_message.hpp>
#include <snet/tls/session.hpp>

namespace snet::tls
{

namespace detail
{

template <typename>
constexpr bool always_false = false;

} // namespace detail

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
    default:
        throw casket::RuntimeError("Unknown handshake message type");
    }

    return HandshakeMessage(std::move(message));
}

inline void writeUint24(nonstd::span<uint8_t> out, uint32_t value)
{
    assert(out.size() < 3);
    out[0] = casket::get_byte<0>(value);
    out[1] = casket::get_byte<1>(value);
    out[2] = casket::get_byte<2>(value);
}

size_t HandshakeMessage::serialize(nonstd::span<uint8_t> output, const MessageType& message, const Session& session)
{
    HandshakeType messageType = std::visit(
        [](auto&& msg) -> HandshakeType
        {
            using T = std::decay_t<decltype(msg)>;
            if constexpr (std::is_same_v<T, ClientHello>)
                return HandshakeType::ClientHelloCode;
            else if constexpr (std::is_same_v<T, ServerHello>)
                return HandshakeType::ServerHelloCode;
            else if constexpr (std::is_same_v<T, EncryptedExtensions>)
                return HandshakeType::EncryptedExtensionsCode;
            else if constexpr (std::is_same_v<T, Certificate>)
                return HandshakeType::CertificateCode;
            else if constexpr (std::is_same_v<T, CertificateVerify>)
                return HandshakeType::CertificateVerifyCode;
            else if constexpr (std::is_same_v<T, ServerKeyExchange>)
                return HandshakeType::ServerKeyExchangeCode;
            else if constexpr (std::is_same_v<T, Finished>)
                return HandshakeType::FinishedCode;
            else
            {
                static_assert(detail::always_false<T>, "Unknown handshake message type");
            }
        },
        message);

    const size_t payloadSize = std::visit(
        [&output, &session](auto&& msg) -> size_t
        {
            auto payload = output.subspan(TLS_HANDSHAKE_HEADER_SIZE);
            return msg.serialize(payload, session);
        },
        message);

    output[0] = static_cast<uint8_t>(messageType);
    writeUint24(output.subspan(1), static_cast<uint32_t>(payloadSize));

    return TLS_HANDSHAKE_HEADER_SIZE + payloadSize;
}

} // namespace snet::tls