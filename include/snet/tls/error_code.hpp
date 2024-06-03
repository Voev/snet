#pragma once
#include <system_error>
#include <openssl/err.h>

namespace snet::tls
{

namespace details
{

class ErrorCategory final : public std::error_category
{
public:
    const char* name() const noexcept override;
    std::string message(int value) const override;
};

const std::error_category& GetErrorCategory();

} // namespace details

enum class Error
{
    InvalidArgument = ERR_R_PASSED_INVALID_ARGUMENT,
    OperationFail = ERR_R_OPERATION_FAIL,
};

std::error_code TranslateError(unsigned long error);

inline std::error_code MakeErrorCode(Error e)
{
    return std::error_code(static_cast<int>(e), details::GetErrorCategory());
}

std::error_code GetLastError();

} // namespace snet::tls