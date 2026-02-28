
#pragma once
#include <casket/nonstd/span.hpp>
#include <casket/utils/exception.hpp>
#include <snet/tls/meta_info.hpp>


namespace snet::tls
{

class Session;

struct ServerHelloDone final
{
    static ServerHelloDone deserialize(nonstd::span<const uint8_t> input)
    {
        casket::ThrowIfFalse(input.size() == 0, "Malformed ServerHelloDone message");
        return ServerHelloDone();
    }

    size_t serialize(nonstd::span<uint8_t> output, const Session& session)
    {
        (void)output;
        (void)session;
        return 0;
    }
};

} // namespace snet::tls
