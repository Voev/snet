#pragma once
#include <casket/nonstd/span.hpp>

namespace snet::tls
{

class Session;

struct EncryptedExtensions final
{
    void parse(nonstd::span<const uint8_t> input)
    {
        extensions = input;
    }

    static EncryptedExtensions deserialize(nonstd::span<const uint8_t> input)
    {
        EncryptedExtensions encryptedExtensions;
        encryptedExtensions.parse(input);
        return encryptedExtensions;
    }

    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const
    {
        (void)output;
        (void)session;
        return 0;
    }

    nonstd::span<const uint8_t> extensions;
};

} // namespace snet::tls