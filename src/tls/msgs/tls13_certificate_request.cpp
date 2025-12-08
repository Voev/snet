#include <snet/tls/msgs/tls13_certificate_request.hpp>

#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::tls
{

void TLSv13CertificateRequest::deserialize(nonstd::span<const uint8_t> input)
{
    utils::DataReader reader("TLSv1.3 CertificateRequest", input);

    certRequestContext = reader.get_span(1, 0, 255);

    const size_t extensionsLength = reader.peek_uint16_t();
    ThrowIfTrue(reader.remaining_bytes() != extensionsLength + 2, "TLSv1.3 CertificateRequest: message malformed");

    extensionsData = reader.get_span_remaining();
}

size_t TLSv13CertificateRequest::serialize(nonstd::span<uint8_t> output) const
{
    /// @todo: support it.
    (void)output;
    return 0;
}

} // namespace snet::tls