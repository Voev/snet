#pragma once
#include <stdexcept>
#include <cstdint>

#include <casket/nonstd/span.hpp>
#include <casket/utils/load_store.hpp>

namespace snet
{

/// @brief Serialization error sentinel returned by `serialize` methods.
///
/// Every extension's `serialize` returns either the number of bytes written
/// (including `0` for empty bodies) or this value on failure (buffer too
/// small, body exceeds the 16-bit length field, server invariant violated).
inline constexpr std::size_t kSerializationFailed = static_cast<std::size_t>(-1);

/// @brief Writes a length-prefixed array of values into @p outputBuffer.
///
/// Wire layout:
///   `<tagSize-byte big-endian length>` followed by `valsSize * sizeof(T)`
///   bytes of @p vals (each element written big-endian).
///
/// @tparam T         Element type; must be an integral type.
/// @param[in] outputBuffer Destination buffer.
/// @param[in] vals          Elements to write; may be null only if @p valsSize is 0.
/// @param[in] valsSize      Number of elements in @p vals.
/// @param[in] tagSize       Width of the length field in bytes (1, 2, or 3).
/// @return Number of bytes written on success,
///         `kSerializationFailed` if @p tagSize is not 1/2/3, the value does
///         not fit the length field, @p outputBuffer is too small, or a
///         multiplication overflows.
/// @note `noexcept`. On failure @p outputBuffer is left untouched
///       (strong guarantee).
template <typename T>
size_t AppendLengthAndValue(nonstd::span<uint8_t> outputBuffer, const T* vals, size_t valsSize, size_t tagSize) noexcept
{
    static_assert(std::is_integral_v<T>, "T must be an integral type");

    if (tagSize != 1 && tagSize != 2 && tagSize != 3)
    {
        return kSerializationFailed;
    }

    const size_t maxValue = (tagSize == 1) ? 0xFFu : (tagSize == 2) ? 0xFFFFu : 0xFFFFFFu;

    constexpr size_t typeSize = sizeof(T);

    if (valsSize > maxValue / typeSize)
    {
        return kSerializationFailed;
    }

    const size_t valueBytes = typeSize * valsSize;
    const size_t requiredSize = tagSize + valueBytes;

    if (outputBuffer.size() < requiredSize)
    {
        return kSerializationFailed;
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