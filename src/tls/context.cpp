
#include <snet/tls/context.hpp>

namespace snet::tls
{

Context::Context(const SSL_METHOD* meth)
    : ctx_(SSL_CTX_new(meth))
{
    if (!ctx_)
        throw std::bad_alloc();
}

Context::~Context() noexcept
{
    SSL_CTX_free(ctx_);
}

void Context::loadPrivateKey(std::string_view filename,
                             std::error_code& ec) noexcept
{
    if (0 >=
        SSL_CTX_use_PrivateKey_file(ctx_, filename.data(), SSL_FILETYPE_PEM))
    {
        ec = GetLastError();
    }
}

void Context::usePrivateKey(EVP_PKEY* privateKey, std::error_code& ec) noexcept
{
    if (!privateKey)
    {
        ec = MakeErrorCode(Error::InvalidArgument);
        return;
    }
    if (0 >= SSL_CTX_use_PrivateKey(ctx_, privateKey))
    {
        ec = GetLastError();
    }
}

void Context::loadCertificate(std::string_view filename,
                              std::error_code& ec) noexcept
{
    if (0 >=
        SSL_CTX_use_certificate_file(ctx_, filename.data(), SSL_FILETYPE_PEM))
    {
        ec = GetLastError();
    }
}

void Context::useCertificate(X509* certificate, std::error_code& ec) noexcept
{
    if (!certificate)
    {
        ec = MakeErrorCode(Error::InvalidArgument);
        return;
    }
    if (0 >= SSL_CTX_use_certificate(ctx_, certificate))
    {
        ec = GetLastError();
    }
}

void Context::setMaxVersion(ProtocolVersion version,
                            std::error_code& ec) noexcept
{
    if (0 >= SSL_CTX_set_max_proto_version(ctx_, static_cast<long>(version)))
    {
        ec = GetLastError();
    }
}

void Context::setMinVersion(ProtocolVersion version,
                            std::error_code& ec) noexcept
{
    if (0 >= SSL_CTX_set_min_proto_version(ctx_, static_cast<long>(version)))
    {
        ec = GetLastError();
    }
}

void Context::setVerifyCallback(VerifyMode mode, VerifyCallback callback) noexcept {
    SSL_CTX_set_verify(ctx_, static_cast<int>(mode), callback);
}

} // namespace snet::tls