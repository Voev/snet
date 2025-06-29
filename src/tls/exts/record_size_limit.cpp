#include <snet/tls/exts/record_size_limit.hpp>
#include <snet/utils/data_reader.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls
{

ExtensionCode RecordSizeLimit::staticType()
{
    return ExtensionCode::RecordSizeLimit;
}

ExtensionCode RecordSizeLimit::type() const
{
    return staticType();
}

bool RecordSizeLimit::empty() const
{
    return limit_ == 0;
}

size_t RecordSizeLimit::serialize(Side side, nonstd::span<uint8_t> output) const
{
    (void)side;

    ThrowIfTrue(output.size_bytes() < 2, "buffer is too small");
    output[0] = casket::get_byte<0>(limit_);
    output[1] = casket::get_byte<1>(limit_);
    return 2;
}

RecordSizeLimit::RecordSizeLimit(const uint16_t limit)
    : limit_(limit)
{
    ThrowIfTrue(limit < 64, "RFC 8449 does not allow record size limits smaller than 64 bytes");
    ThrowIfTrue(limit > MAX_PLAINTEXT_SIZE + 1 /* encrypted content type byte */,
                "RFC 8449 does not allow record size limits larger than 2^14+1");
}

RecordSizeLimit::RecordSizeLimit(Side side, nonstd::span<const uint8_t> input)
{
    utils::DataReader reader("record_size_limit", input);
    limit_ = reader.get_uint16_t();
    reader.assert_done();

    ThrowIfTrue(limit_ < 64, "received a record size limit smaller than 64 bytes");
    ThrowIfTrue(side == Side::Server && limit_ > MAX_PLAINTEXT_SIZE + 1 /* encrypted content type byte */,
                "server requested a record size limit larger than the protocol's maximum");
}

uint16_t RecordSizeLimit::limit() const
{
    return limit_;
}

} // namespace snet::tls