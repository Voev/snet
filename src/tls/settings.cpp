
#include <snet/tls/settings.hpp>
#include <snet/crypto/exception.hpp>
#include <casket/utils/exception.hpp>

using namespace casket::utils;

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
    crypto::ThrowIfFalse(ctx_);
}

Settings::~Settings() noexcept
{
}

void Settings::loadPrivateKey(std::string_view filename)
{
    crypto::ThrowIfFalse(0 < SSL_CTX_use_PrivateKey_file(ctx_, filename.data(), SSL_FILETYPE_PEM));
}

void Settings::usePrivateKey(EVP_PKEY* privateKey)
{
    crypto::ThrowIfFalse(0 < SSL_CTX_use_PrivateKey(ctx_, privateKey));
}

void Settings::loadCertificate(std::string_view filename)
{
    crypto::ThrowIfFalse(0 < SSL_CTX_use_certificate_file(ctx_, filename.data(), SSL_FILETYPE_PEM));
}

void Settings::useCertificate(X509* certificate)
{
    crypto::ThrowIfFalse(0 < SSL_CTX_use_certificate(ctx_, certificate));
}

void Settings::setMaxVersion(const ProtocolVersion& version)
{
    crypto::ThrowIfFalse(0 < SSL_CTX_set_max_proto_version(ctx_, version.code()));
}

void Settings::setMinVersion(const ProtocolVersion& version)
{
    crypto::ThrowIfFalse(0 < SSL_CTX_set_min_proto_version(ctx_, version.code()));
}

void Settings::setVerifyCallback(VerifyMode mode, VerifyCallback callback) noexcept
{
    SSL_CTX_set_verify(ctx_, static_cast<int>(mode), callback);
}

void Settings::setMode(Mode mode)
{
    crypto::ThrowIfFalse(0 < SSL_CTX_set_mode(ctx_, static_cast<long>(mode)));
}

void Settings::setSessionCacheMode(unsigned long mode)
{
    crypto::ThrowIfFalse(0 < SSL_CTX_set_session_cache_mode(ctx_, static_cast<long>(mode)));
}

void Settings::setOptions(unsigned long options)
{
    crypto::ThrowIfFalse(0 < SSL_CTX_set_options(ctx_, options));
}

void Settings::setGroupsList(std::string_view groupsList)
{
    crypto::ThrowIfFalse(0 < SSL_CTX_set1_groups_list(ctx_, groupsList.data()));
}

void Settings::setCipherList(std::string_view cipherList)
{
    crypto::ThrowIfFalse(0 < SSL_CTX_set_cipher_list(ctx_, cipherList.data()));
}

void Settings::setCipherSuites(std::string_view cipherSuites)
{
    crypto::ThrowIfFalse(0 < SSL_CTX_set_ciphersuites(ctx_, cipherSuites.data()));
}

} // namespace snet::tls