#include <snet/tls/record.hpp>

namespace snet::tls
{

size_t Record::packHandshake(std::span<uint8_t> buffer)
{
    casket::utils::ThrowIfTrue(buffer.size_bytes() < TLS_HANDSHAKE_HEADER_SIZE, "buffer too small");
    uint32_t length{0};

    switch (handshake.type)
    {
        case HandshakeType::ClientHello:
        {
            length = handshake.clientHello.serialize(buffer.subspan(TLS_HANDSHAKE_HEADER_SIZE));
            break;
        }
        default:
        {
            break;
        }
    }

    buffer[0] = static_cast<uint8_t>(handshake.type);
    buffer[1] = utils::get_byte<0>(length);
    buffer[2] = utils::get_byte<1>(length);
    buffer[3] = utils::get_byte<2>(length);

    return length + TLS_HANDSHAKE_HEADER_SIZE;
}

size_t Record::pack(std::span<uint8_t> buffer)
{
    casket::utils::ThrowIfTrue(buffer.size_bytes() < TLS_HEADER_SIZE, "buffer too small");
    uint16_t length{0};

    switch (type)
    {
        case RecordType::ChangeCipherSpec:
        {
            break;
        }
        case RecordType::Alert:
        {
            break;
        }
        case RecordType::Handshake:
        {
            length = packHandshake(buffer.subspan(TLS_HEADER_SIZE));
            break;
        }
        case RecordType::ApplicationData:
        {
            break;
        }
        default:
        {
            break;
        }
    }

    buffer[0] = static_cast<uint8_t>(type);
    buffer[1] = version.majorVersion();
    buffer[2] = version.minorVersion();
    buffer[3] = utils::get_byte<0>(length);
    buffer[4] = utils::get_byte<1>(length);

    return length + TLS_HEADER_SIZE;
}

} // namespace snet::tls