#pragma once
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

namespace snet
{

template <typename T>
static inline T BytesToNumber(const uint8_t* bytes, size_t length)
{
    static_assert(std::is_integral_v<T> && !std::is_same_v<T, bool>, "T must be an integral type");
    assert(bytes != nullptr);
    assert(length > 0);

    T result = 0;
    size_t bytesToCopy = std::min(length, sizeof(T));

    std::memcpy(&result, bytes, bytesToCopy);

    return result;
}

} // namespace snet