
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
        (void)session;

        std::copy(verifyData.begin(), verifyData.end(), output.begin());
        return verifyData.size();
    }

    nonstd::span<const uint8_t> verifyData;
};

} // namespace snet::tls
