#include <snet/tls/error_code.hpp>

namespace snet::tls
{

namespace details
{

const char* ErrorCategory::name() const noexcept
{
    return "OpenSSL";
}

std::string ErrorCategory::message(int value) const
{
    const char* reason = ::ERR_reason_error_string(value);
    if (reason)
    {
        const char* lib = ::ERR_lib_error_string(value);
#if (OPENSSL_VERSION_NUMBER < 0x30000000L)
        const char* func = ::ERR_func_error_string(value);
#else  // (OPENSSL_VERSION_NUMBER < 0x30000000L)
        const char* func = 0;
#endif // (OPENSSL_VERSION_NUMBER < 0x30000000L)
        std::string result(reason);
        if (lib || func)
        {
            result += " (";
            if (lib)
                result += lib;
            if (lib && func)
                result += ", ";
            if (func)
                result += func;
            result += ")";
        }
        return result;
    }

    return "OpenSSL error";
}

const std::error_category& GetErrorCategory()
{
    static details::ErrorCategory instance;
    return instance;
}

} // namespace details

std::error_code TranslateError(unsigned long error)
{

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (ERR_SYSTEM_ERROR(error))
    {
        return std::error_code(static_cast<int>(ERR_GET_REASON(error)),
                               std::system_category());
    }
#endif // (OPENSSL_VERSION_NUMBER >= 0x30000000L)

    return std::error_code(static_cast<int>(error),
                           details::GetErrorCategory());
}

std::error_code GetLastError()
{
    const auto err = ::ERR_get_error();
    if(err)
        return TranslateError(err);
    return MakeErrorCode(Error::OperationFail);
}

} // namespace snet::tls