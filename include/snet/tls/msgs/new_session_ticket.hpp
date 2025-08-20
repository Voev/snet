
#pragma once
#include <variant>
#include <snet/tls/msgs/tls1_new_session_ticket.hpp>
#include <snet/tls/msgs/tls13_new_session_ticket.hpp>
#include <snet/tls/version.hpp>
#include <snet/tls/meta_info.hpp>

namespace snet::tls
{

class Session;

struct NewSessionTicket final
{
    std::variant<TLSv1NewSessionTicket, TLSv13NewSessionTicket> message;

    void parse(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    static NewSessionTicket deserialize(nonstd::span<const uint8_t> input, const MetaInfo& metaInfo);

    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const;
};

} // namespace snet::tls
