#pragma once

#include <type_traits>
#include <cstddef>

#ifndef NONSTD_INLINE
#if __cplusplus >= 201703L
#define NONSTD_INLINE inline
#else
#define NONSTD_INLINE
#endif
#endif // NONSTD_INLINE

namespace nonstd2
{

template <class... Ts>
NONSTD_INLINE constexpr bool always_false_v = false;

#if __cplusplus < 201703L

template <class _Ty,
          class _Uty>
NONSTD_INLINE constexpr bool is_same_v = std::is_same<_Ty, _Uty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_function_v = std::is_function<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_void_v = std::is_void<_Ty>::value;

// ALIAS TEMPLATE void_t
template <class... _Types>
using void_t = void;

template <class _Ty>
NONSTD_INLINE constexpr bool is_array_v = std::is_array<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_lvalue_reference_v = std::is_lvalue_reference<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_rvalue_reference_v = std::is_rvalue_reference<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_reference_v = std::is_reference<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_member_object_pointer_v = std::is_member_object_pointer<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_member_function_pointer_v = std::is_member_function_pointer<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_pointer_v = std::is_pointer<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_null_pointer_v = nonstd2::is_same_v<std::remove_cv_t<_Ty>, std::nullptr_t>;

template <class _Ty>
NONSTD_INLINE constexpr bool is_union_v = std::is_union<_Ty>::type;

template <class _Ty>
NONSTD_INLINE constexpr bool is_class_v = std::is_class<_Ty>::type;

template <class _Ty>
NONSTD_INLINE constexpr bool is_fundamental_v = std::is_fundamental<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_object_v = std::is_object<_Ty>::value;

template <class _From,
          class _To>
NONSTD_INLINE constexpr bool is_convertible_v = std::is_convertible<_From, _To>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_enum_v = std::is_enum<_Ty>::type;

template <class _Ty>
NONSTD_INLINE constexpr bool is_compound_v = std::is_compound<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_member_pointer_v = std::is_member_pointer<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_scalar_v = std::is_scalar<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_const_v = std::is_const<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_volatile_v = std::is_volatile<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_pod_v = std::is_pod<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_empty_v = std::is_empty<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_polymorphic_v = std::is_polymorphic<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_abstract_v = std::is_abstract<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_final_v = std::is_final<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_standard_layout_v = std::is_standard_layout<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_trivial_v = std::is_trivial<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_trivially_copyable_v = std::is_trivially_copyable<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool has_virtual_destructor_v = std::has_virtual_destructor<_Ty>::value;

template <class _Ty,
          class... _Args>
NONSTD_INLINE constexpr bool is_constructible_v = std::is_constructible<_Ty, _Args...>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_copy_constructible_v = std::is_constructible<_Ty, std::add_lvalue_reference_t<const _Ty>>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_default_constructible_v = std::is_constructible<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_move_constructible_v = std::is_constructible<_Ty, _Ty>::value;

template <class _To,
          class _From>
NONSTD_INLINE constexpr bool is_assignable_v = std::is_assignable<_To, _From>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_copy_assignable_v =
     std::is_assignable<std::add_lvalue_reference_t<_Ty>, std::add_lvalue_reference_t<const _Ty>>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_move_assignable_v = std::is_assignable<std::add_lvalue_reference_t<_Ty>, _Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_destructible_v = std::is_destructible<_Ty>::value;

template <class _Ty,
          class... _Args>
NONSTD_INLINE constexpr bool is_trivially_constructible_v = std::is_trivially_constructible<_Ty, _Args...>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_trivially_copy_constructible_v =
     std::is_trivially_constructible<_Ty, std::add_lvalue_reference_t<const _Ty>>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_trivially_default_constructible_v = std::is_trivially_constructible<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_trivially_move_constructible_v = std::is_trivially_constructible<_Ty, _Ty>::value;

template <class _To,
          class _From>
NONSTD_INLINE constexpr bool is_trivially_assignable_v = std::is_trivially_assignable<_To, _From>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_trivially_copy_assignable_v =
     std::is_trivially_assignable<std::add_lvalue_reference_t<_Ty>, std::add_lvalue_reference_t<const _Ty>>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_trivially_move_assignable_v =
     std::is_trivially_assignable<std::add_lvalue_reference_t<_Ty>, _Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_trivially_destructible_v = std::is_trivially_destructible<_Ty>::value;

template <class _Ty,
          class... _Args>
NONSTD_INLINE constexpr bool is_nothrow_constructible_v = std::is_nothrow_constructible<_Ty, _Args...>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_nothrow_copy_constructible_v =
     std::is_nothrow_constructible<_Ty, std::add_lvalue_reference_t<const _Ty>>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_nothrow_default_constructible_v = std::is_nothrow_constructible<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_nothrow_move_constructible_v = std::is_nothrow_constructible<_Ty, _Ty>::value;

template <class _To,
          class _From>
NONSTD_INLINE constexpr bool is_nothrow_assignable_v = std::is_nothrow_assignable<_To, _From>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_nothrow_copy_assignable_v =
     std::is_nothrow_assignable<std::add_lvalue_reference_t<_Ty>, std::add_lvalue_reference_t<const _Ty>>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_nothrow_move_assignable_v = std::is_nothrow_assignable<std::add_lvalue_reference_t<_Ty>, _Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_nothrow_destructible_v = std::is_nothrow_destructible<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_signed_v = std::is_signed<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr bool is_unsigned_v = std::is_unsigned<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr size_t alignment_of_v = std::alignment_of<_Ty>::value;

template <class _Ty>
NONSTD_INLINE constexpr size_t rank_v = std::rank<_Ty>::value;

template <class _Ty,
          unsigned int _Ix = 0>
NONSTD_INLINE constexpr size_t extent_v = std::extent<_Ty, _Ix>::value;

template <class _Base,
          class _Derived>
NONSTD_INLINE constexpr bool is_base_of_v = std::is_base_of<_Base, _Derived>::value;

#endif //  __cplusplus < 201703L

namespace detail
{

template <template <class...> class Expr, class SFINAE, class... Args>
NONSTD_INLINE constexpr bool is_detected = false;

template <template <class...> class Expr, class... Args>
NONSTD_INLINE constexpr bool is_detected<Expr, nonstd2::void_t<Expr<Args...>>, Args...> = true;

} // namespace detail

template <template <class...> class Expr, class... Args>
NONSTD_INLINE constexpr bool is_detected_v = nonstd2::detail::is_detected<Expr, void, Args...>;

} // namespace nonstd2
