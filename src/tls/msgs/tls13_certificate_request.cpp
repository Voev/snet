#include <snet/tls/msgs/tls13_certificate_request.hpp>

#include <cstring>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/decode_error.hpp>

namespace snet::tls
{

using snet::AppendLengthAndValue;
using snet::kSerializationFailed;

std::error_code TLSv13CertificateRequest::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    certRequestContext = {};
    extensionsData = {};

    utils::DataReader reader("TLSv1.3 CertificateRequest", input);

    certRequestContext = reader.get_span(1, 0, 255);
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    const std::uint16_t extTotal = reader.peek_uint16_t();
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    if (extTotal != reader.remaining_bytes() - 2)
    {
        return utils::make_error_code(utils::DecodeError::LengthOutOfRange);
    }

    extensionsData = reader.get_span_remaining();
    reader.assert_done();
    return reader.take_ec();
}

std::size_t TLSv13CertificateRequest::serialize(nonstd::span<uint8_t> output) const noexcept
{
    if (extensionsData.size() < 2)
    {
        // Must contain at least the 2-byte length prefix.
        return kSerializationFailed;
    }

    std::size_t pos = 0;

    {
        const std::size_t n =
            AppendLengthAndValue(output.subspan(pos), certRequestContext.data(), certRequestContext.size(), 1);
        if (n == kSerializationFailed)
            return kSerializationFailed;
        pos += n;
    }

    // extensionsData already contains its own 2-byte length prefix, so just
    // copy it verbatim.
    if (output.size_bytes() - pos < extensionsData.size())
    {
        return kSerializationFailed;
    }
    if (!extensionsData.empty())
    {
        std::memcpy(output.data() + pos, extensionsData.data(), extensionsData.size());
    }
    pos += extensionsData.size();
    return pos;
}

} // namespace snet::tls