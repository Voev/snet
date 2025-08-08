#include <snet/tls/types.hpp>
#include <snet/tls/msgs/certificate_verify.hpp>
#include <snet/utils/data_reader.hpp>

using namespace snet::crypto;

namespace snet::tls
{

void CertificateVerify::deserialize(nonstd::span<const uint8_t> input)
{
    utils::DataReader reader("CertificateVerify", input.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    scheme = SignatureScheme(reader.get_uint16_t());
    signature = reader.get_span<uint8_t>(2, 0, 65535);

    reader.assert_done();
}

} // namespace snet::tls