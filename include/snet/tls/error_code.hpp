/// @file
/// @brief Declaration of error handling functions for TLS.

#pragma once
#include <system_error>

namespace snet::tls
{

/// @brief Translates an error code from an unsigned long to a std::error_code.
/// @param error The error code to translate.
/// @return The corresponding std::error_code.
std::error_code TranslateError(unsigned long error);

/// @brief Retrieves the last error that occurred.
/// @return The last error as a std::error_code.
std::error_code GetLastError();

} // namespace snet::tls