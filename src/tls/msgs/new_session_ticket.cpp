#include <snet/tls/msgs/new_session_ticket.hpp>

#include <snet/utils/decode_error.hpp>

namespace snet::tls
{

namespace
{

inline std::error_code ec(utils::DecodeError e) noexcept
{
    return utils::make_error_code(e);
}

} // namespace

std::error_code NewSessionTicket::deserialize(nonstd::span<const uint8_t> input,
                                              const MetaInfo& metaInfo) noexcept
{
    if (metaInfo.version == ProtocolVersion::TLSv1_3)
    {
        TLSv13NewSessionTicket msg;
        if (const auto err = msg.deserialize(input); err) return err;
        message = std::move(msg);
        return {};
    }

    TLSv1NewSessionTicket msg;
    if (const auto err = msg.deserialize(input); err) return err;
    message = std::move(msg);
    return {};
}

std::size_t NewSessionTicket::serialize(nonstd::span<uint8_t> output,
                                        const Session& session) const noexcept
{
    (void)session;

    return nonstd::visit(
        [&output](const auto& msg) noexcept -> std::size_t {
            return msg.serialize(output);
        },
        message);
}

} // namespace snet::tls