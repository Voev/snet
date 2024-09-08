#pragma once
#include <system_error>

namespace snet::tls
{

std::error_code TranslateError(unsigned long error);

std::error_code GetLastError();

} // namespace snet::tls