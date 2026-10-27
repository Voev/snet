#include <snet/tls/msgs/certificate.hpp>

#include <snet/utils/decode_error.hpp>

using namespace snet::utils;

namespace snet::tls
{

std::error_code Certificate::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo) noexcept
{
    if (metaInfo.version == ProtocolVersion::TLSv1_3)
    {
        TLSv13Certificate msg;
        if (const auto err = msg.deserialize(input); err)
            return err;
        message = std::move(msg);
        return make_error_code(DecodeError::None);
    }
    else
    {

        TLSv1Certificate msg;
        if (const auto err = msg.deserialize(input); err)
            return err;
        message = std::move(msg);
        return make_error_code(DecodeError::None);
    }
}

std::size_t Certificate::serialize(nonstd::span<uint8_t> output, const Session& session) const noexcept
{
    return nonstd::visit(
        [&](const auto& msg) noexcept -> std::size_t
        {
            using T = std::decay_t<decltype(msg)>;
            if constexpr (std::is_same_v<T, TLSv1Certificate>)
            {
                (void)session;
                return msg.serialize(output);
            }
            else
            {
                return msg.serialize(output, session);
            }
        },
        message);
}

} // namespace snet::tls