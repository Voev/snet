#include <snet/tls/msgs/certificate_request.hpp>
#include <snet/tls/session.hpp>

namespace snet::tls
{

void CertificateRequest::parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    if (metaInfo.version == ProtocolVersion::TLSv1_3)
    {
        auto& inner = message.emplace<TLSv13CertificateRequest>();
        inner.deserialize(input);
    }
    else if (metaInfo.version == ProtocolVersion::TLSv1_2)
    {
        auto& inner = message.emplace<TLSv12CertificateRequest>();
        inner.deserialize(input);
    }
    else
    {
        auto& inner = message.emplace<TLSv1CertificateRequest>();
        inner.deserialize(input);
    }
}

CertificateRequest CertificateRequest::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    CertificateRequest certRequest;
    certRequest.parse(input, metaInfo);
    return certRequest;
}

size_t CertificateRequest::serialize(nonstd::span<uint8_t> output, const Session& session) const
{
    (void)session;

    if (std::holds_alternative<TLSv13CertificateRequest>(message))
    {
        return std::get<TLSv13CertificateRequest>(message).serialize(output);
    }
    else if (std::holds_alternative<TLSv12CertificateRequest>(message))
    {
        return std::get<TLSv12CertificateRequest>(message).serialize(output);
    }
    else
    {
        return std::get<TLSv1CertificateRequest>(message).serialize(output);
    }
}

} // namespace snet::tls