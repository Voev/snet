#pragma once
#include <string>
#include <system_error>

namespace snet::crypto
{

/// @brief Represents the error category for TLS errors.
class ErrorCategory final : public std::error_category
{
public:
    /// @brief Gets the name of the error category.
    /// @return The name of the error category.
    const char* name() const noexcept override;

    /// @brief Gets the error message corresponding to an error value.
    /// @param value The error value.
    /// @return The error message.
    std::string message(int value) const override;

    static ErrorCategory& getInstance();

private:
    ErrorCategory() = default;
    ~ErrorCategory() = default;
};

} // namespace snet::crypto


namespace snet::crypto::verify
{

class ErrorCategory final : public std::error_category
{
public:
    const char* name() const noexcept override;
    std::string message(int value) const override;

    static ErrorCategory& getInstance();

private:
    ErrorCategory() = default;
    ~ErrorCategory() = default;
};

} // namespace snet::crypto::verify
