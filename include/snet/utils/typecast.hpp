#pragma once
#include <cstring>
#include <snet/utils/concepts.hpp>

namespace snet::utils {

/**
 * Copy a range of a trivially copyable type into another range of trivially
 * copyable type of matching byte length.
 */
template <ranges::contiguous_output_range ToR, ranges::contiguous_range FromR>
requires std::is_trivially_copyable_v<std::ranges::range_value_t<FromR>>&&
    std::is_trivially_copyable_v<std::ranges::range_value_t<ToR>> inline constexpr void
    typecast_copy(ToR&& out, FromR&& in) {
    ranges::assert_equal_byte_lengths(out, in);
    std::memcpy(std::ranges::data(out), std::ranges::data(in), ranges::size_bytes(out));
}

/**
 * Copy a range of trivially copyable type into an instance of trivially
 * copyable type with matching length.
 */
template <typename ToT, ranges::contiguous_range FromR>
    requires std::is_trivially_copyable_v<std::ranges::range_value_t<FromR>>&& std::is_trivially_copyable_v<ToT> &&
    (!std::ranges::range<ToT>)inline constexpr void typecast_copy(ToT& out, FromR&& in) noexcept {
    typecast_copy(std::span<ToT, 1>(&out, 1), in);
}

/**
 * Copy an instance of trivially copyable type into a range of trivially
 * copyable type with matching length.
 */
template <ranges::contiguous_output_range ToR, typename FromT>
    requires std::is_trivially_copyable_v<FromT> &&
    (!std::ranges::range<FromT>)&&std::is_trivially_copyable_v<
        std::ranges::range_value_t<ToR>> inline constexpr void typecast_copy(ToR&& out, const FromT& in) {
    typecast_copy(out, std::span<const FromT, 1>(&in, 1));
}

/**
 * Create a trivial type by bit-casting a range of trivially copyable type with
 * matching length into it.
 */
template <typename ToT, ranges::contiguous_range FromR>
requires std::is_default_constructible_v<ToT> &&
         std::is_trivially_copyable_v<ToT>&&
         std::is_trivially_copyable_v<std::ranges::range_value_t<FromR>>
inline constexpr ToT typecast_copy(FromR&& src) noexcept {
    ToT dst;
    typecast_copy(dst, src);
    return dst;
}

} // namespace snet::utils
