#include <snet/tls/msgs/certificate.hpp>
#include <snet/tls/session.hpp>

namespace snet::tls
{

void Certificate::parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    if (metaInfo.version == ProtocolVersion::TLSv1_3)
    {
        auto& cert = message.emplace<TLSv13Certificate>();
        cert.deserialize(input);
    }
    else
    {
        auto& cert = message.emplace<TLSv1Certificate>();
        cert.deserialize(input);
    }
}

Certificate Certificate::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    Certificate certificate;
    if (metaInfo.version == ProtocolVersion::TLSv1_3)
    {
        auto& cert = certificate.message.emplace<TLSv13Certificate>();
        cert.deserialize(input);
    }
    else
    {
        auto& cert = certificate.message.emplace<TLSv1Certificate>();
        cert.deserialize(input);
    }
    return certificate;
}

size_t Certificate::serialize(nonstd::span<uint8_t> output, const Session& session) const
{
    (void)session;

    if (std::holds_alternative<TLSv13Certificate>(message))
    {
        return std::get<TLSv13Certificate>(message).serialize(output);
    }
    else
    {
        return std::get<TLSv1Certificate>(message).serialize(output);
    }
}

} // namespace snet::tls