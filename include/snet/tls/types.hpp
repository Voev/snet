#pragma once
#include <cstdint>
#include <memory>
#include <openssl/ssl.h>

namespace snet::tls
{

enum class ProtocolVersion : std::uint16_t
{
    SSLv3_0 = SSL3_VERSION,
    TLSv1_0 = TLS1_VERSION,
    TLSv1_1 = TLS1_1_VERSION,
    TLSv1_2 = TLS1_2_VERSION,
    TLSv1_3 = TLS1_3_VERSION
};

template <typename T, void (*f)(T*)> struct static_function_deleter
{
    void operator()(T* t) const
    {
        f(t);
    }
};

#define OSSL_DEFINE_PTR_TYPE(alias, object, deleter)                           \
    using alias##Deleter = static_function_deleter<object, &deleter>;          \
    using alias##Ptr = std::unique_ptr<object, alias##Deleter>

OSSL_DEFINE_PTR_TYPE(Bio, BIO, BIO_free_all);
OSSL_DEFINE_PTR_TYPE(BioAddr, BIO_ADDR, BIO_ADDR_free);

OSSL_DEFINE_PTR_TYPE(Ssl, SSL, SSL_free);
OSSL_DEFINE_PTR_TYPE(SslCtx, SSL_CTX, SSL_CTX_free);

} // namespace snet::tls