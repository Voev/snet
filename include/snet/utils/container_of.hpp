#pragma once

#include <cstddef>
#include <cstdint>

namespace snet
{

template <typename Container, typename Member>
Container* container_of(Member* ptr, Member Container::* member)
{
    if (!ptr)
        return nullptr;

    // Вычисляем смещение поля в структуре (один раз при первом вызове)
    static const size_t offset = []()
    {
        Container dummy;
        return reinterpret_cast<size_t>(&(dummy.*member)) - reinterpret_cast<size_t>(&dummy);
    }();

    return reinterpret_cast<Container*>(reinterpret_cast<char*>(ptr) - offset);
}

template <typename Container, typename Member>
const Container* container_of(const Member* ptr, Member Container::* member)
{
    if (!ptr)
        return nullptr;

    static const size_t offset = []()
    {
        Container dummy;
        return reinterpret_cast<size_t>(&(dummy.*member)) - reinterpret_cast<size_t>(&dummy);
    }();

    return reinterpret_cast<const Container*>(reinterpret_cast<const char*>(ptr) - offset);
}

} // namespace snet