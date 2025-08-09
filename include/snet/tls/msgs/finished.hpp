
#pragma once
#include <casket/nonstd/span.hpp>

namespace snet::tls
{

class Session;

struct Finished final
{
    inline void parse(nonstd::span<const uint8_t> input)
    {
        verifyData = input;
    }

    static Finished deserialize(nonstd::span<const uint8_t> input)
    {
        Finished finished;
        finished.parse(input);
        return finished;
    }

    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const
    {
        (void)output;
        (void)session;
        return 0;
    }

    nonstd::span<const uint8_t> verifyData;
};

} // namespace snet::tls
