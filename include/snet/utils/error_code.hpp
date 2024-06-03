#pragma once
#include <system_error>

namespace snet::utils
{

inline std::error_code GetLastSystemError()
{
    return std::make_error_code(static_cast<std::errc>(errno));
}

} // namespace snet::utils