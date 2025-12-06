#include <snet/tls/types.hpp>
#include <snet/tls/msgs/certificate_verify.hpp>
#include <snet/utils/data_reader.hpp>

using namespace snet::crypto;

namespace snet::tls
{

void CertificateVerify::parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    utils::DataReader reader("CertificateVerify", input);

    if (metaInfo.version >= ProtocolVersion::TLSv1_2)
    {
        scheme = SignatureScheme(reader.get_uint16_t());
        signature = reader.get_span(2, 0, 65535);
    }
    else
    {
        signature = reader.get_span(2, 0, 65535);
    }

    reader.assert_done();
}

CertificateVerify CertificateVerify::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    CertificateVerify certVerify;
    certVerify.parse(input, metaInfo);
    return certVerify;
}

size_t CertificateVerify::serialize(nonstd::span<uint8_t> output, const Session& session) const
{
    /// @todo: support it.
    (void)output;
    (void)session;
    return 0;
}

} // namespace snet::tls