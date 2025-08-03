#pragma once
#include <cstdint>
#include <cstddef>
#include <casket/nonstd/span.hpp>

namespace snet::crypto
{

class Rand final
{
public:
    static void seed(const uint8_t* entropy, const size_t entropySize);

    static inline void seed(nonstd::span<uint8_t> buffer)
    {
        seed(buffer.data(), buffer.size());
    }

    static void generate(uint8_t* random, const size_t randomSize);

    static inline void generate(nonstd::span<uint8_t> buffer)
    {
        generate(buffer.data(), buffer.size());
    }
};

} // namespace snet::crypto