#include <snet/tls/msgs/tls12_certificate_request.hpp>

#include <cstring>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>
#include <snet/utils/decode_error.hpp>

using namespace snet::utils;

namespace snet::tls
{

std::error_code TLSv12CertificateRequest::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    certTypes = {};
    supportedSigAlgs = {};
    certAuthorities = {};

    utils::DataReader reader(input);

    certTypes = reader.get_span(1, 1, 255);
    if (!reader.ok())
        return reader.take_ec();

    supportedSigAlgs = reader.get_span_length_and_value(2);
    if (!reader.ok())
        return reader.take_ec();
    if (supportedSigAlgs.size() < 2 || supportedSigAlgs.size() % 2 != 0)
    {
        reader.set_error(utils::DecodeError::SizeNotMultiple);
        return reader.take_ec();
    }

    const std::uint16_t caTotal = reader.get_uint16_t();
    if (!reader.ok())
        return reader.take_ec();
    if (caTotal != reader.remaining_bytes())
    {
        return utils::make_error_code(utils::DecodeError::LengthOutOfRange);
    }

    certAuthorities = reader.get_span_fixed(caTotal);
    if (!reader.ok())
        return reader.take_ec();

    reader.assert_done();
    return reader.take_ec();
}

std::size_t TLSv12CertificateRequest::serialize(nonstd::span<uint8_t> output) const noexcept
{
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
            AppendLengthAndValue(output.subspan(pos), supportedSigAlgs.data(), supportedSigAlgs.size(), 2);
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