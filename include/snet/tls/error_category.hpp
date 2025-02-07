/// @file
/// @brief Declaration of the ErrorCategory class.

#pragma once
#include <string>
#include <system_error>
#include <casket/utils/singleton.hpp>

namespace snet::tls
{

/// @brief Represents the error category for TLS errors.
class ErrorCategory final : public casket::utils::Singleton<ErrorCategory>,
                            public std::error_category
{
public:
    /// @brief Gets the name of the error category.
    /// @return The name of the error category.
    const char* name() const noexcept override;

    /// @brief Gets the error message corresponding to an error value.
    /// @param value The error value.
    /// @return The error message.
    std::string message(int value) const override;
};

} // namespace snet::tls