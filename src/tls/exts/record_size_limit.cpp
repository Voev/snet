#include <snet/tls/exts/record_size_limit.hpp>

#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

RecordSizeLimit::RecordSizeLimit(const uint16_t limit)
    : limit_(limit)
{
    ThrowIfFalse(limit >= 64, "RFC 8449 does not allow record size limits smaller than 64 bytes");
    ThrowIfFalse(limit <= MAX_PLAINTEXT_SIZE + 1 /* encrypted content type byte */,
                 "RFC 8449 does not allow record size limits larger than 2^14+1");
}

RecordSizeLimit::RecordSizeLimit(utils::DataReader& reader, uint16_t extensionSize, Side from)
{
    if (extensionSize != 2)
    {
        throw std::runtime_error("invalid record_size_limit extension");
    }

    limit_ = reader.get_uint16_t();

    // RFC 8449 4.
    //    This value is the length of the plaintext of a protected record.
    //    The value includes the content type and padding added in TLS 1.3 (that
    //    is, the complete length of TLSInnerPlaintext).
    //
    //    A server MUST NOT enforce this restriction; a client might advertise
    //    a higher limit that is enabled by an extension or version the server
    //    does not understand. A client MAY abort the handshake with an
    //    "illegal_parameter" alert.
    //
    // Note: We are currently supporting this extension in TLS 1.3 only, hence
    //       we check for the TLS 1.3 limit. The TLS 1.2 limit would not include
    //       the "content type byte" and hence be one byte less!
    if (limit_ > MAX_PLAINTEXT_SIZE + 1 /* encrypted content type byte */ && from == Side::Server)
    {
        throw std::runtime_error("Server requested a record size limit larger than the protocol's maximum");
    }

    // RFC 8449 4.
    //    Endpoints MUST NOT send a "record_size_limit" extension with a value
    //    smaller than 64.  An endpoint MUST treat receipt of a smaller value
    //    as a fatal error and generate an "illegal_parameter" alert.
    if (limit_ < 64)
    {
        throw std::runtime_error("Received a record size limit smaller than 64 bytes");
    }
}

size_t RecordSizeLimit::serialize(Side whoami, std::span<uint8_t> buffer) const
{
    (void)whoami;

    ThrowIfTrue(buffer.size_bytes() < 2, "buffer is too small");
    buffer[0] = utils::get_byte<0>(limit_);
    buffer[1] = utils::get_byte<1>(limit_);
    return 2;
}

} // namespace snet::tls