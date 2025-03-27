#include <openssl/err.h>
#include <snet/crypto/error_code.hpp>
#include <snet/crypto/error_category.hpp>

namespace snet::crypto
{

std::error_code TranslateError(unsigned long error)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    if (ERR_SYSTEM_ERROR(error))
    {
        return std::error_code{static_cast<int>(ERR_GET_REASON(error)), std::system_category()};
    }
#endif // (OPENSSL_VERSION_NUMBER >= 0x30000000L)

    return std::error_code{static_cast<int>(error), ErrorCategory::getInstance()};
}

std::error_code GetLastError()
{
    const auto err = ::ERR_get_error();
    if (err)
        return TranslateError(err);
    return TranslateError(ERR_R_OPERATION_FAIL);
}

} // namespace snet::crypto

namespace snet::crypto::verify
{

std::error_code MakeErrorCode(Error e)
{
    return std::error_code(static_cast<int>(e), ErrorCategory::getInstance());
}

} // namespace snet::crypto::verify