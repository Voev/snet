#include <snet/tls/msgs/tls1_certificate_request.hpp>

#include <cstring>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/decode_error.hpp>

namespace snet::tls
{

using snet::AppendLengthAndValue;
using snet::kSerializationFailed;

std::error_code TLSv1CertificateRequest::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    certTypes = {};
    certAuthorities = {};

    utils::DataReader reader(input);

    // certificate_types: <1-byte length> <certType>*  (1..255 entries)
    certTypes = reader.get_span(1, 1, 255);
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    // certificate_authorities: <2-byte total length> <DistinguishedName>*
    // (TLS 1.0/1.1 has no supported_signature_algorithms field.)
    const std::uint16_t caTotal = reader.get_uint16_t();
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    if (caTotal != reader.remaining_bytes())
    {
        return utils::make_error_code(utils::DecodeError::LengthOutOfRange);
    }

    certAuthorities = reader.get_span_fixed(caTotal);
    if (!reader.ok())
    {
        return reader.take_ec();
    }

    reader.assert_done();
    return reader.take_ec();
}

std::size_t TLSv1CertificateRequest::serialize(nonstd::span<uint8_t> output) const noexcept
{
    if (certTypes.empty())
    {
        return kSerializationFailed;
    }

    std::size_t pos = 0;

    {
        const std::size_t n = AppendLengthAndValue(output.subspan(pos), certTypes.data(), certTypes.size(), 1);
        if (n == kSerializationFailed)
        {
            return kSerializationFailed;
        }
        pos += n;
    }

    {
        const std::size_t n =
            AppendLengthAndValue(output.subspan(pos), certAuthorities.data(), certAuthorities.size(), 2);
        if (n == kSerializationFailed)
        {
            return kSerializationFailed;
        }
        pos += n;
    }

    return pos;
}

} // namespace snet::tls