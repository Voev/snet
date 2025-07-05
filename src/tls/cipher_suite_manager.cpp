#include <cassert>
#include <snet/tls/cipher_suite.hpp>
#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/crypto/exception.hpp>
#include <snet/crypto/pointers.hpp>

#include <casket/utils/endianness.hpp>

using namespace snet::crypto;

namespace snet::tls
{

struct CipherSuiteManager::Impl final
{
public:
    Impl()
        : ctx(SSL_CTX_new_ex(nullptr, nullptr, TLS_method()))
        , ssl(nullptr)
    {
        crypto::ThrowIfFalse(ctx != nullptr);

        SSL_CTX_set_cipher_list(ctx, "ALL:COMPLEMENTOFALL");

        ssl = SSL_new(ctx);
        crypto::ThrowIfFalse(ssl != nullptr);
    }

    ~Impl() noexcept
    {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }

    SSL_CTX* ctx;
    SSL* ssl;
};

CipherSuiteManager::CipherSuiteManager()
    : impl_(std::make_unique<Impl>())
{
}

CipherSuiteManager::~CipherSuiteManager() noexcept
{
}

CipherSuiteManager& CipherSuiteManager::getInstance()
{
    static CipherSuiteManager instance;
    return instance;
}

const CipherSuite* CipherSuiteManager::getCipherSuiteById(std::uint16_t id)
{
    std::uint16_t bytes = casket::host_to_be(id);
    std::uint8_t* ptr = reinterpret_cast<std::uint8_t*>(&bytes);
    return SSL_CIPHER_find(impl_->ssl, ptr);
}

std::vector<const CipherSuite*> CipherSuiteManager::getCipherSuites(bool supported)
{
    STACK_OF(SSL_CIPHER) * ciphers;

    if (supported)
        ciphers = SSL_get1_supported_ciphers(impl_->ssl);
    else
        ciphers = SSL_get_ciphers(impl_->ssl);

    crypto::ThrowIfTrue(ciphers == nullptr, "Failed to get supported cipher suites");

    std::vector<const CipherSuite*> cipherSuites(sk_SSL_CIPHER_num(ciphers));

    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i)
    {
        cipherSuites[i] = sk_SSL_CIPHER_value(ciphers, i);
    }

    if (supported)
        sk_SSL_CIPHER_free(ciphers);

    return cipherSuites;
}

void CipherSuiteManager::setSecurityLevel(const int securityLevel)
{
    crypto::ThrowIfFalse(securityLevel >= 0 && securityLevel <= 5,
                         "Security level must be in range [0..5]");
    SSL_set_security_level(impl_->ssl, securityLevel);
}

} // namespace snet::tls