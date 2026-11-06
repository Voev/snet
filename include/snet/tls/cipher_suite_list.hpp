/// @file
/// @brief Fixed-capacity list of cipher suite wire IDs.

#pragma once

#include <cstdint>
#include <cstddef>

#include <casket/nonstd/span.hpp>

namespace snet::tls
{

/// @brief Fixed-capacity list of cipher suite wire IDs.
///
/// Value-type: trivially copyable and movable. Used inside ClientHello to
/// hold parsed suites; the backing storage is owned by the object, so
/// copies and moves never dangle.
///
/// Iteration and access mirror a span:
///   for (auto id : list) use(id);
///   list.size(), list.empty(), list[i]
template <std::size_t Capacity>
struct CipherSuiteList final
{
    std::array<std::uint16_t, Capacity> data{};
    std::size_t count = 0;

    std::uint16_t operator[](std::size_t i) const noexcept
    {
        return data[i];
    }
    std::uint16_t& operator[](std::size_t i) noexcept
    {
        return data[i];
    }

    auto begin() const noexcept
    {
        return data.begin();
    }
    auto end() const noexcept
    {
        return data.begin() + count;
    }
    auto begin() noexcept
    {
        return data.begin();
    }
    auto end() noexcept
    {
        return data.begin() + count;
    }

    std::size_t size() const noexcept
    {
        return count;
    }
    bool empty() const noexcept
    {
        return count == 0;
    }
    static constexpr std::size_t capacity() noexcept
    {
        return Capacity;
    }

    void clear() noexcept
    {
        count = 0;
    }

    /// @brief Append a suite wire ID. Returns false if full.
    bool push_back(std::uint16_t id) noexcept
    {
        if (count == Capacity)
            return false;
        data[count++] = id;
        return true;
    }

    /// @brief Get a view over the populated elements.
    nonstd::span<const std::uint16_t> span() const noexcept
    {
        return {data.data(), count};
    }
};

} // namespace snet::tls