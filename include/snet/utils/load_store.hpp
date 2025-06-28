#pragma once
#include <bit>
#include <vector>
#include <cstdint>
#include <cstring>
#include <snet/utils/byteswap.hpp>
#include <snet/utils/endianness.hpp>
#include <snet/utils/alignment.hpp>

namespace snet::utils
{

/// @brief Byte extraction
///
/// @param[in] byte_num which byte to extract, 0 == highest byte
/// @param[in] input the value to extract from
///
/// @return byte byte_num of input
///
template <typename T>
inline constexpr uint8_t get_byte_var(size_t byte_num, T input)
{
    return static_cast<uint8_t>(input >> (((~byte_num) & (sizeof(T) - 1)) << 3));
}

/// @brief Byte extraction
///
/// @param[in] input the value to extract from
///
/// @return byte byte number B of input
///
template <size_t B, typename T>
inline constexpr uint8_t get_byte(T input)
    requires(B < sizeof(T))
{
    const size_t shift = ((~B) & (sizeof(T) - 1)) << 3;
    return static_cast<uint8_t>((input >> shift) & 0xFF);
}

/// @brief Make a uint16_t from two bytes
///
/// @param[in] i0 the first byte
/// @param[in] i1 the second byte
///
/// @return i0 || i1
///
inline constexpr uint16_t make_uint16(uint8_t i0, uint8_t i1)
{
    return static_cast<uint16_t>((static_cast<uint16_t>(i0) << 8) | i1);
}

/// @brief Make a uint32_t from four bytes
///
/// @param[in] i0 the first byte
/// @param[in] i1 the second byte
/// @param[in] i2 the third byte
/// @param[in] i3 the fourth byte
///
/// @return i0 || i1 || i2 || i3
///
inline constexpr uint32_t make_uint32(uint8_t i0, uint8_t i1, uint8_t i2, uint8_t i3)
{
    return ((static_cast<uint32_t>(i0) << 24) | (static_cast<uint32_t>(i1) << 16) | (static_cast<uint32_t>(i2) << 8) |
            (static_cast<uint32_t>(i3)));
}

/// @brief Make a uint64_t from eight bytes
///
/// @param[in] i0 the first byte
/// @param[in] i1 the second byte
/// @param[in] i2 the third byte
/// @param[in] i3 the fourth byte
/// @param[in] i4 the fifth byte
/// @param[in] i5 the sixth byte
/// @param[in] i6 the seventh byte
/// @param[in] i7 the eighth byte
///
/// @return i0 || i1 || i2 || i3 || i4 || i5 || i6 || i7
///
inline constexpr uint64_t make_uint64(uint8_t i0, uint8_t i1, uint8_t i2, uint8_t i3, uint8_t i4, uint8_t i5,
                                      uint8_t i6, uint8_t i7)
{
    return ((static_cast<uint64_t>(i0) << 56) | (static_cast<uint64_t>(i1) << 48) | (static_cast<uint64_t>(i2) << 40) |
            (static_cast<uint64_t>(i3) << 32) | (static_cast<uint64_t>(i4) << 24) | (static_cast<uint64_t>(i5) << 16) |
            (static_cast<uint64_t>(i6) << 8) | (static_cast<uint64_t>(i7)));
}

namespace detail
{

template <typename T, bool Aligned>
struct load_be_impl;

template <typename T>
struct load_be_impl<T, true>
{
    static T load(const uint8_t* data)
    {
        return be_to_host<T>(*reinterpret_cast<const T*>(data));
    }
};

template <typename T>
struct load_be_impl<T, false>
{
    static T load(const uint8_t* data)
    {
        T value;
        for (size_t i = 0; i < sizeof(T); ++i)
        {
            reinterpret_cast<uint8_t*>(&value)[i] = data[sizeof(T) - 1 - i];
        }
        return value;
    }
};

} // namespace detail

template <typename T>
T load_be(const uint8_t* data, size_t index = 0)
{
    static_assert(std::is_unsigned<T>::value, "Only unsigned types are supported");
    static_assert(sizeof(T) <= 8, "Type size too large");

    const uint8_t* ptr = data + index * sizeof(T);
    const bool aligned = casket::is_aligned_for<T>(ptr);

    return aligned ? detail::load_be_impl<T, true>::load(ptr) : detail::load_be_impl<T, false>::load(ptr);
}

template <typename T, typename = void>
struct store_be_impl;

template <typename T>
struct store_be_impl<T, typename std::enable_if<sizeof(T) == 1>::type>
{
    static void store(T value, uint8_t* data)
    {
        data[0] = static_cast<uint8_t>(value);
    }
};

template <typename T>
struct store_be_impl<T, typename std::enable_if<sizeof(T) == 2>::type>
{
    static void store(T value, uint8_t* data)
    {
        uint16_t val;
#if defined(__GNUC__) || defined(__clang__)
        val = __builtin_bswap16(value);
#else
        val = (value << 8) | (value >> 8);
#endif
        std::memcpy(data, &val, sizeof(val));
    }
};

template <typename T>
struct store_be_impl<T, typename std::enable_if<sizeof(T) == 4>::type>
{
    static void store(T value, uint8_t* data)
    {
        uint32_t val;
#if defined(__GNUC__) || defined(__clang__)
        val = __builtin_bswap32(value);
#else
        val = ((value & 0xFF000000) >> 24) | ((value & 0x00FF0000) >> 8) | ((value & 0x0000FF00) << 8) |
              ((value & 0x000000FF) << 24);
#endif
        std::memcpy(data, &val, sizeof(val));
    }
};

template <typename T>
struct store_be_impl<T, typename std::enable_if<sizeof(T) == 8>::type>
{
    static void store(T value, uint8_t* data)
    {
        uint64_t val;
#if defined(__GNUC__) || defined(__clang__)
        val = __builtin_bswap64(value);
#else
        val = ((value & 0xFF00000000000000ull) >> 56) | ((value & 0x00FF000000000000ull) >> 40) |
              ((value & 0x0000FF0000000000ull) >> 24) | ((value & 0x000000FF00000000ull) >> 8) |
              ((value & 0x00000000FF000000ull) << 8) | ((value & 0x0000000000FF0000ull) << 24) |
              ((value & 0x000000000000FF00ull) << 40) | ((value & 0x00000000000000FFull) << 56);
#endif
        std::memcpy(data, &val, sizeof(val));
    }
};

template <typename T>
void store_be(T value, uint8_t* data)
{
    store_be_impl<T>::store(value, data);
}

} // namespace snet::utils