#pragma once

#include <cstring>
#include <memory>
#include <type_traits>

namespace snet::utils
{

// GCC warns when reinterpret_cast between function pointer and object pointer occur.
// This method suppress the warnings and ensures that such casts are safe.
template <class To, class From>
inline
    typename std::enable_if<!std::is_member_pointer<To>::value && !std::is_reference<To>::value &&
                                !std::is_member_pointer<From>::value,
                            To>::type
    aggressive_ptr_cast(From v) noexcept
{
    static_assert(std::is_pointer<To>::value && std::is_pointer<From>::value,
                  "`agressive_ptr_cast` function must be used only for pointer casting.");

    static_assert(
        std::is_void<typename std::remove_pointer<To>::type>::value ||
            std::is_void<typename std::remove_pointer<From>::type>::value,
        "`agressive_ptr_cast` function must be used only for casting to or from void pointers.");

    static_assert(sizeof(v) == sizeof(To),
                  "Pointer to function and pointer to object differ in size on your platform.");

    return reinterpret_cast<To>(v);
}

template <class To, class From>
inline typename std::enable_if<std::is_reference<To>::value && !std::is_member_pointer<From>::value,
                               To>::type
aggressive_ptr_cast(From v) noexcept
{
    static_assert(std::is_pointer<From>::value,
                  "`agressive_ptr_cast` function must be used only for pointer casting.");

    static_assert(
        std::is_void<typename std::remove_pointer<From>::type>::value,
        "`agressive_ptr_cast` function must be used only for casting to or from void pointers.");

    static_assert(sizeof(v) == sizeof(typename std::remove_reference<To>::type*),
                  "Pointer to function and pointer to object differ in size on your platform.");
    return static_cast<To>(**reinterpret_cast<typename std::remove_reference<To>::type**>(v));
}

template <class To, class From>
inline typename std::enable_if<
    std::is_member_pointer<To>::value && !std::is_member_pointer<From>::value, To>::type
aggressive_ptr_cast(From v) noexcept
{
    static_assert(std::is_pointer<From>::value,
                  "`agressive_ptr_cast` function must be used only for pointer casting.");

    static_assert(
        std::is_void<typename std::remove_pointer<From>::type>::value,
        "`agressive_ptr_cast` function must be used only for casting to or from void pointers.");

    To res = 0;
    std::memcpy(&res, &v, sizeof(From));
    return res;
}

template <class To, class From>
inline typename std::enable_if<
    !std::is_member_pointer<To>::value && std::is_member_pointer<From>::value, To>::type
aggressive_ptr_cast(From /* v */) noexcept
{
    static_assert(std::is_pointer<To>::value,
                  "`agressive_ptr_cast` function must be used only for pointer casting.");

    static_assert(
        std::is_void<typename std::remove_pointer<To>::type>::value,
        "`agressive_ptr_cast` function must be used only for casting to or from void pointers.");

    static_assert(
        !sizeof(From),
        "Casting from member pointers to void pointer is not implemnted in `agressive_ptr_cast`.");

    return 0;
}

} // namespace snet::utils
