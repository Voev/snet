#include <snet/tls/error_category.hpp>
#include <openssl/err.h>

namespace snet::tls
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

} // namespace snet::tls