#include <snet/tls/msgs/tls12_certificate_request.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls
{

void TLSv12CertificateRequest::deserialize(nonstd::span<const uint8_t> input)
{
    utils::DataReader reader("TLSv1.2 CertificateRequest", input);

    casket::ThrowIfTrue(reader.remaining_bytes() < 4, "TLSv1.2 CertificateRequest: bad message");

    certTypes = reader.get_span(1, 1, 255);
    supportedSigAlgs = reader.get_span(2, 2, 65534);

    casket::ThrowIfTrue(supportedSigAlgs.size() % 2 != 0, "Bad length for signature IDs in certificate request");

    const uint16_t certAuthoritiesSize = reader.get_uint16_t();
    casket::ThrowIfTrue(reader.remaining_bytes() != certAuthoritiesSize, "Inconsistent length in certificate request");

    while (reader.has_remaining())
    {
        auto certAuthority = reader.get_span(2, 0, 65535);
    }

    reader.assert_done();
}

size_t TLSv12CertificateRequest::serialize(nonstd::span<uint8_t> output) const
{
    /// @todo: support it.
    (void)output;
    return 0;
}

} // namespace snet::tls::msg