#include <snet/tls/msgs/handshake_message.hpp>

#include <snet/tls/session.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/decode_error.hpp>

using namespace snet::utils;

namespace snet::tls
{

std::error_code HandshakeMessage::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo,
                                              HandshakeMessage& out) noexcept
{
    if (input.size_bytes() < TLS_HANDSHAKE_HEADER_SIZE)
    {
        return make_error_code(utils::DecodeError::NotEnoughBytes);
    }

    utils::DataReader reader(input);

    const auto messageType = static_cast<HandshakeType>(reader.get_byte());
    const auto messageLength = reader.get_uint24_t();
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    if (reader.remaining_bytes() != messageLength)
    {
        return make_error_code(utils::DecodeError::LengthOutOfRange);
    }

    auto payload = input.subspan(TLS_HANDSHAKE_HEADER_SIZE, messageLength);

    MessageType message;
    std::error_code err;

    switch (messageType)
    {
    case HandshakeType::ClientHelloCode:
        err = message.emplace<ClientHello>().deserialize(payload);
        break;
    case HandshakeType::ServerHelloCode:
        err = message.emplace<ServerHello>().deserialize(payload);
        break;
    case HandshakeType::EncryptedExtensionsCode:
        err = message.emplace<EncryptedExtensions>().deserialize(payload);
        break;
    case HandshakeType::CertificateCode:
        err = message.emplace<Certificate>().deserialize(payload, metaInfo);
        break;
    case HandshakeType::CertificateRequestCode:
        err = message.emplace<CertificateRequest>().deserialize(payload, metaInfo);
        break;
    case HandshakeType::CertificateVerifyCode:
        err = message.emplace<CertificateVerify>().deserialize(payload, metaInfo);
        break;
    case HandshakeType::ServerKeyExchangeCode:
        err = message.emplace<ServerKeyExchange>().deserialize(payload, metaInfo);
        break;
    case HandshakeType::FinishedCode:
        err = message.emplace<Finished>().deserialize(payload);
        break;
    case HandshakeType::ServerHelloDoneCode:
        err = message.emplace<ServerHelloDone>().deserialize(payload);
        break;
    case HandshakeType::KeyUpdateCode:
        err = message.emplace<KeyUpdate>().deserialize(payload);
        break;
    case HandshakeType::ClientKeyExchangeCode:
        err = message.emplace<ClientKeyExchange>().deserialize(payload, metaInfo);
        break;
    case HandshakeType::NewSessionTicketCode:
        err = message.emplace<NewSessionTicket>().deserialize(payload, metaInfo);
        break;
    default:
        err = make_error_code(utils::DecodeError::MalformedMessage);
        break;
    }

    if (err)
    {
        return err;
    }

    out.message_ = std::move(message);
    return make_error_code(DecodeError::None);
}

std::size_t HandshakeMessage::serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept
{
    if (output.size_bytes() < TLS_HANDSHAKE_HEADER_SIZE)
        return kSerializationFailed;

    const std::size_t payloadSize = nonstd::visit(
        [&output, &session](const auto& msg) noexcept -> std::size_t
        {
            using T = std::decay_t<decltype(msg)>;
            if constexpr (std::is_same_v<T, NoMessage>)
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

    if (payloadSize == kSerializationFailed)
    {

        return kSerializationFailed;
    }

    if (payloadSize > 0xFFFFFF)
    {
        return kSerializationFailed;
    }

    output[0] = static_cast<std::uint8_t>(getType());
    const auto length = static_cast<std::uint32_t>(payloadSize);
    output[1] = casket::get_byte<1>(length);
    output[2] = casket::get_byte<2>(length);
    output[3] = casket::get_byte<3>(length);

    return TLS_HANDSHAKE_HEADER_SIZE + payloadSize;
}

namespace
{

inline constexpr HandshakeType kIndexToType[] = {
    HandshakeType::NoneCode,
    HandshakeType::ClientHelloCode,
    HandshakeType::ServerHelloCode,
    HandshakeType::EncryptedExtensionsCode,
    HandshakeType::ServerKeyExchangeCode,
    HandshakeType::ClientKeyExchangeCode,
    HandshakeType::CertificateCode,
    HandshakeType::CertificateRequestCode,
    HandshakeType::CertificateVerifyCode,
    HandshakeType::FinishedCode,
    HandshakeType::NewSessionTicketCode,
    HandshakeType::ServerHelloDoneCode,
    HandshakeType::KeyUpdateCode,
};
static_assert(std::size(kIndexToType) == 13);

} // namespace

HandshakeType HandshakeMessage::getType() const noexcept
{
    const auto idx = message_.index();
    if (idx >= std::size(kIndexToType))
    {
        return HandshakeType::NoneCode;
    }
    return kIndexToType[idx];
}

} // namespace snet::tls