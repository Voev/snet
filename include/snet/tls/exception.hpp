/// @file
/// @brief General exception type for TLS errors.

#pragma once

#include <string>
#include <system_error>
#include <stdexcept>

#include <snet/tls/error_code.hpp>

namespace snet::tls {

/// @brief Main class for TLS exceptions.
class Exception final : public std::system_error {
public:
    /// @brief Constructor.
    ///
    /// @param ec Error code.
    explicit Exception(std::error_code ec)
        : std::system_error(ec) {
    }

    /// @brief Constructor.
    ///
    /// @param ec Error code.
    /// @param what_arg Error message.
    Exception(std::error_code ec, const std::string& what_arg)
        : std::system_error(ec, what_arg) {
    }

    /// @brief Constructor.
    ///
    /// @param ec Error code.
    /// @param what_arg Error message.
    Exception(std::error_code ec, const char* what_arg)
        : std::system_error(ec, what_arg) {
    }
};

/// @brief Throws an exception if @p exprResult is true.
///
/// @param exprResult The result of the expression to check.
///
/// @code{.cpp}
/// /* EXAMPLE */
/// auto* somePointer = new (std::nothrow) int;
/// Exception::ThrowIfTrue(somePointer == nullptr);
/// @endcode
inline void ThrowIfTrue(bool exprResult) {
    if (exprResult) {
        throw Exception(GetLastError());
    }
}

/// @brief Throws an exception if @p exprResult is true.
///
/// @param exprResult The result of the expression to check.
/// @param msg Additional message.
inline void ThrowIfTrue(bool exprResult, std::string msg) {
    if (exprResult) {
        throw Exception(GetLastError(), msg);
    }
}

/// @brief Throws an exception if @p exprResult is false.
///
/// @param exprResult The result of the expression to check.
///
/// @code{.cpp}
/// /* EXAMPLE */
/// void* inputData = nullptr;
/// SomeValidator validator;
/// Exception::ThrowIfFalse(validator.isValid(inputData));
/// @endcode
inline void ThrowIfFalse(bool exprResult) {
    return ThrowIfTrue(!exprResult);
}

/// @brief Throws an exception if @p exprResult is false.
///
/// @param exprResult The result of the expression to check.
/// @param msg Additional message.
inline void ThrowIfFalse(bool exprResult, std::string msg) {
    return ThrowIfTrue(!exprResult, std::move(msg));
}

} // namespace snet::tls
