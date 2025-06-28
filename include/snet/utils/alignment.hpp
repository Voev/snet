#pragma once
#include <cstdint>
#include <type_traits>

namespace casket
{

template <typename T>
bool is_aligned_for(const void* ptr)
{
    return (reinterpret_cast<uintptr_t>(ptr) % alignof(T) == 0);
}

} // namespace casket