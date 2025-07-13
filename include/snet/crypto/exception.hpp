/// @file
/// @brief General exception type for TLS errors.

#pragma once

#include <string_view>
#include <system_error>
#include <stdexcept>

#include <snet/crypto/error_code.hpp>

namespace snet::crypto
{

/// @brief Main class for TLS exceptions.
class CryptoException final : public std::system_error
{
public:
    /// @brief Constructor.
    ///
    /// @param[in] ec Error code.
    ///
    explicit CryptoException(std::error_code ec)
        : std::system_error(ec)
    {
    }

    /// @brief Constructor.
    ///
    /// @param[in] ec Error code.
    /// @param[in] what Error message.
    ///
    CryptoException(std::error_code ec, std::string_view what)
        : std::system_error(ec, what.data())
    {
    }
};

/// @brief Throws an exception if @p expression is true.
///
/// @param[in] expression Result of the expression to check.
///
inline void ThrowIfTrue(bool expression)
{
    if (expression)
    {
        throw CryptoException(GetLastError());
    }
}

/// @brief Throws an exception if @p expression is true.
///
/// @param[in] expression Result of the expression to check.
/// @param[in] message Additional message.
///
inline void ThrowIfTrue(bool expression, std::string_view message)
{
    if (expression)
    {
        throw CryptoException(GetLastError(), message);
    }
}

/// @brief Throws an exception if @p expression is false.
///
/// @param[in] expression Result of the expression to check.
///
inline void ThrowIfFalse(bool expression)
{
    if (!expression)
    {
        throw CryptoException(GetLastError());
    }
}

/// @brief Throws an exception if @p expression is false.
///
/// @param[in] expression Result of the expression to check.
/// @param[in] message Additional message.
///
inline void ThrowIfFalse(bool expression, std::string_view message)
{
    if (!expression)
    {
        throw CryptoException(GetLastError(), message);
    }
}

} // namespace snet::crypto
