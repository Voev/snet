#include <snet/tls/msgs/new_session_ticket.hpp>
#include <snet/tls/session.hpp>

namespace snet::tls
{

void NewSessionTicket::parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    if (metaInfo.version == ProtocolVersion::TLSv1_3)
    {
        auto& cert = message.emplace<TLSv13NewSessionTicket>();
        cert.deserialize(input);
    }
    else
    {
        auto& cert = message.emplace<TLSv1NewSessionTicket>();
        cert.deserialize(input);
    }
}

NewSessionTicket NewSessionTicket::deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo)
{
    NewSessionTicket sessionTicket;
    if (metaInfo.version == ProtocolVersion::TLSv1_3)
    {
        sessionTicket.message.emplace<TLSv13NewSessionTicket>().deserialize(input);
    }
    else
    {
        sessionTicket.message.emplace<TLSv1NewSessionTicket>().deserialize(input);
    }
    return sessionTicket;
}

size_t NewSessionTicket::serialize(nonstd::span<uint8_t> output, const Session& session) const
{
    (void)session;

    if (std::holds_alternative<TLSv13NewSessionTicket>(message))
    {
        return std::get<TLSv13NewSessionTicket>(message).serialize(output);
    }
    else
    {
        return std::get<TLSv1NewSessionTicket>(message).serialize(output);
    }
}

} // namespace snet::tls