#pragma once
#include <stdexcept>
#include <cstdint>

#include <casket/nonstd/span.hpp>
#include <casket/utils/load_store.hpp>

namespace snet
{

template <typename T>
size_t append_length_and_value(nonstd::span<uint8_t> outputBuffer, const T* vals, size_t valsSize, size_t tagSize)
{
    constexpr size_t typeSize = sizeof(T);
    const size_t valueBytes = typeSize * valsSize;
    const size_t requiredSize = tagSize + valueBytes;

    if (outputBuffer.size() < requiredSize)
    {
        throw std::runtime_error("append_length_and_value: buffer too small");
    }

    if (tagSize != 1 && tagSize != 2 && tagSize != 3)
    {
        throw std::runtime_error("append_length_and_value: invalid tag size");
    }

    if ((tagSize == 1 && valueBytes > 255) || (tagSize == 2 && valueBytes > 65535) ||
        (tagSize == 3 && valueBytes > 16777215))
    {
        throw std::runtime_error("append_length_and_value: value too large");
    }

    for (size_t i = 0; i != tagSize; ++i)
    {
        outputBuffer[i] = casket::get_byte_var(sizeof(valueBytes) - tagSize + i, valueBytes);
    }

    for (size_t i = 0; i != valsSize; ++i)
    {
        for (size_t j = 0; j != typeSize; ++j)
        {
            outputBuffer[tagSize + i * typeSize + j] = casket::get_byte_var(j, vals[i]);
        }
    }

    return requiredSize;
}

} // namespace snet