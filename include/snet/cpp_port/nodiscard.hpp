#pragma once

#if __cplusplus >= 201703L
#     define NONSTD_NODISCARD [[nodiscard]]
#elif defined(__clang__)
/* || defined( __GNUC__ ) && ( __GNUC__ >= 4 ) */
/*
   ^ commented out, because GCC devs are morons. See
   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=25509
   https://gcc.gnu.org/bugzilla/show_bug.cgi?id=66425
*/
#     define NONSTD_NODISCARD __attribute__( ( warn_unused_result ) )
#elif defined( _MSC_VER ) && ( _MSC_VER >= 1700 )
#     define NONSTD_NODISCARD _Check_return_
#else
#     define NONSTD_NODISCARD
#endif
