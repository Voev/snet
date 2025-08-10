#pragma once
#include <cstdint>
#include <casket/nonstd/span.hpp>

namespace snet::tls
{

class Session;

struct EncryptedExtensions final
{
    nonstd::span<const uint8_t> extensions;

public: /// Methods

    void parse(nonstd::span<const uint8_t> input);

    static EncryptedExtensions deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output, const Session& session) const;
};

} // namespace snet::tls