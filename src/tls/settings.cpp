
#include <snet/tls/settings.hpp>
#include <snet/tls/error_code.hpp>
#include <snet/utils/error_code_exception.hpp>

using namespace snet::utils;

namespace snet::tls
{

static inline const SSL_METHOD* GetMethod(Side side)
{
    switch (side)
    {
    case Side::Client:
        return TLS_client_method();
    case Side::Server:
        return TLS_server_method();
    default:
        break;
    }
    return nullptr;
}

Settings::Settings(Side side)
    : ctx_(SSL_CTX_new(GetMethod(side)))
{
    if (!ctx_)
    {
        throw ErrorCodeException(GetLastError());
    }
}

Settings::~Settings() noexcept
{
}

void Settings::loadPrivateKey(std::string_view filename)
{
    if (0 >=
        SSL_CTX_use_PrivateKey_file(ctx_, filename.data(), SSL_FILETYPE_PEM))
    {
        throw ErrorCodeException(GetLastError());
    }
}

void Settings::usePrivateKey(EVP_PKEY* privateKey)
{
    if (0 >= SSL_CTX_use_PrivateKey(ctx_, privateKey))
    {
        throw ErrorCodeException(GetLastError());
    }
}

void Settings::loadCertificate(std::string_view filename)
{
    if (0 >=
        SSL_CTX_use_certificate_file(ctx_, filename.data(), SSL_FILETYPE_PEM))
    {
        throw ErrorCodeException(GetLastError());
    }
}

void Settings::useCertificate(X509* certificate)
{
    if (0 >= SSL_CTX_use_certificate(ctx_, certificate))
    {
        throw ErrorCodeException(GetLastError());
    }
}

void Settings::setMaxVersion(ProtocolVersion version)
{
    if (0 >= SSL_CTX_set_max_proto_version(ctx_, static_cast<long>(version)))
    {
        throw ErrorCodeException(GetLastError());
    }
}

void Settings::setMinVersion(ProtocolVersion version)
{
    if (0 >= SSL_CTX_set_min_proto_version(ctx_, static_cast<long>(version)))
    {
        throw ErrorCodeException(GetLastError());
    }
}

void Settings::setVerifyCallback(VerifyMode mode,
                                 VerifyCallback callback) noexcept
{
    SSL_CTX_set_verify(ctx_, static_cast<int>(mode), callback);
}

void Settings::setMode(Mode mode)
{
    if (0 >= SSL_CTX_set_mode(ctx_, static_cast<long>(mode)))
    {
        throw ErrorCodeException(GetLastError());
    }
}

void Settings::setSessionCacheMode(unsigned long mode)
{
    if (0 >= SSL_CTX_set_session_cache_mode(ctx_, static_cast<long>(mode)))
    {
        throw ErrorCodeException(GetLastError());
    }
}

void Settings::setOptions(unsigned long options)
{
    if (0 >= SSL_CTX_set_options(ctx_, options))
    {
        throw ErrorCodeException(GetLastError());
    }
}

void Settings::setGroupsList(std::string_view groupsList)
{
    if (0 >= SSL_CTX_set1_groups_list(ctx_, groupsList.data()))
    {
        throw ErrorCodeException(GetLastError());
    }
}

void Settings::setCipherList(std::string_view cipherList)
{
    if (0 >= SSL_CTX_set_cipher_list(ctx_, cipherList.data()))
    {
        throw ErrorCodeException(GetLastError());
    }
}

void Settings::setCipherSuites(std::string_view cipherSuites)
{
    if (0 >= SSL_CTX_set_ciphersuites(ctx_, cipherSuites.data()))
    {
        throw ErrorCodeException(GetLastError());
    }
}

} // namespace snet::tls