#include <snet/tls/msgs/certificate_request.hpp>
#include <snet/utils/decode_error.hpp>

using namespace snet::utils;

namespace snet::tls
{

std::error_code CertificateRequest::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept
{
    if (metaInfo.version == ProtocolVersion::TLSv1_3)
    {
        TLSv13CertificateRequest msg;
        if (const auto err = msg.deserialize(input); err)
            return err;
        message = std::move(msg);
        return make_error_code(DecodeError::None);
    }
    else if (metaInfo.version == ProtocolVersion::TLSv1_2)
    {
        TLSv12CertificateRequest msg;
        if (const auto err = msg.deserialize(input); err)
            return err;
        message = std::move(msg);
        return make_error_code(DecodeError::None);
    }
    else
    {
        TLSv1CertificateRequest msg;
        if (const auto err = msg.deserialize(input); err)
            return err;
        message = std::move(msg);
        return make_error_code(DecodeError::None);
    }
}

std::size_t CertificateRequest::serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept
{
    (void)session;

    return nonstd::visit(
        [&output](const auto& msg) noexcept -> std::size_t
        {
            return msg.serialize(output);
        },
        message);
}

} // namespace snet::tls