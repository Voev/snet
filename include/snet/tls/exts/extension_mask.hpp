#pragma once

#include <array>
#include <cstdint>

#include <snet/tls/exts/extension_code.hpp>

namespace snet::tls
{

class ExtensionMask final
{
public:
    static constexpr std::size_t kSlots = 32;
    static constexpr std::uint16_t kEmpty = 0xFFFF; // sentinel

    ExtensionMask() noexcept
    {
        slots_.fill(kEmpty);
    }

    void insert(ExtensionCode c) noexcept
    {
        const auto k = static_cast<std::uint16_t>(c);
        auto i = static_cast<std::size_t>(k) & (kSlots - 1);
        while (slots_[i] != kEmpty && slots_[i] != k)
            i = (i + 1) & (kSlots - 1);
        slots_[i] = k;
    }

    bool contains(ExtensionCode c) const noexcept
    {
        const auto k = static_cast<std::uint16_t>(c);
        auto i = static_cast<std::size_t>(k) & (kSlots - 1);
        while (slots_[i] != kEmpty)
        {
            if (slots_[i] == k)
                return true;
            i = (i + 1) & (kSlots - 1);
        }
        return false;
    }

    void clear() noexcept
    {
        slots_.fill(kEmpty);
    }

private:
    std::array<std::uint16_t, kSlots> slots_{};
};

} // namespace snet::tls