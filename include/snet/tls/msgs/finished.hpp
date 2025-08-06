
#pragma once
#include <casket/nonstd/span.hpp>

namespace snet::tls
{

struct Finished final
{
    inline void deserialize(nonstd::span<const uint8_t> input)
    {
        verifyData = input;
    }

    //size_t serialize(const ProtocolVersion& version, nonstd::span<uint8_t> output) const;

    nonstd::span<const uint8_t> verifyData;
};

} // namespace snet::tls
