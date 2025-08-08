
#pragma once
#include <variant>
#include <snet/tls/msgs/tls1_certificate.hpp>
#include <snet/tls/msgs/tls13_certificate.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

struct Certificate final
{
    void deserialize(nonstd::span<const uint8_t> input, const ProtocolVersion& version)
    {
        if (version == ProtocolVersion::TLSv1_3)
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

    size_t serialize(nonstd::span<uint8_t> output) const
    {
        (void)output;
        return 0;
    }

    std::variant<TLSv1Certificate, TLSv13Certificate> message;
};

} // namespace snet::tls
