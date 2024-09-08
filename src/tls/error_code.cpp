#include <snet/tls/error_code.hpp>
#include <snet/tls/error_category.hpp>
#include <openssl/err.h>

namespace snet::tls
{

std::error_code TranslateError(unsigned long error)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (ERR_SYSTEM_ERROR(error))
    {
        return std::error_code{static_cast<int>(ERR_GET_REASON(error)),
                               std::system_category()};
    }
#endif // (OPENSSL_VERSION_NUMBER >= 0x30000000L)

    return std::error_code{static_cast<int>(error), ErrorCategory::Instance()};
}

std::error_code GetLastError()
{
    const auto err = ::ERR_get_error();
    if (err)
        return TranslateError(err);
    return std::error_code{};
}

} // namespace snet::tls