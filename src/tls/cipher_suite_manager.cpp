#include <cassert>
#include <snet/tls/cipher_suite.hpp>
#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/tls/exception.hpp>

#include <snet/utils/endianness.hpp>

namespace
{

snet::tls::CipherSuite CreateCipherSuite(const SSL_CIPHER* cs)
{
    assert(cs != nullptr);

    auto cipher = OBJ_nid2sn(SSL_CIPHER_get_cipher_nid(cs));
    auto digest = OBJ_nid2sn(SSL_CIPHER_get_digest_nid(cs));
    auto kexch = OBJ_nid2sn(SSL_CIPHER_get_kx_nid(cs));
    auto auth = OBJ_nid2sn(SSL_CIPHER_get_auth_nid(cs));
    auto hdigest = EVP_MD_get0_name(SSL_CIPHER_get_handshake_digest(cs));

    return snet::tls::CipherSuite(SSL_CIPHER_get_protocol_id(cs), SSL_CIPHER_get_bits(cs, nullptr), kexch,
                                  auth, cipher, digest, hdigest, SSL_CIPHER_standard_name(cs),
                                  SSL_CIPHER_get_version(cs), SSL_CIPHER_is_aead(cs));
}

} // namespace

namespace snet::tls
{

struct CipherSuiteManager::Impl final
{
public:
    Impl()
        : ctx(SSL_CTX_new_ex(nullptr, nullptr, TLS_method()))
        , ssl(nullptr)
    {
        tls::ThrowIfFalse(ctx != nullptr);

        ssl = SSL_new(ctx);
        tls::ThrowIfFalse(ssl != nullptr);
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

std::optional<CipherSuite> CipherSuiteManager::getCipherSuiteById(std::uint16_t id)
{
    std::uint16_t bytes = utils::host_to_be(id);
    std::uint8_t* ptr = reinterpret_cast<std::uint8_t*>(&bytes);

    auto cipher = SSL_CIPHER_find(impl_->ssl, ptr);
    if (cipher == nullptr)
    {
        return std::nullopt;
    }

    return ::CreateCipherSuite(cipher);
}

std::vector<CipherSuite> CipherSuiteManager::getCipherSuites(bool supported)
{
    STACK_OF(SSL_CIPHER) * ciphers;

    if (supported)
        ciphers = SSL_get1_supported_ciphers(impl_->ssl);
    else
        ciphers = SSL_get_ciphers(impl_->ssl);

    tls::ThrowIfTrue(ciphers == nullptr, "Failed to get supported cipher suites");

    std::vector<CipherSuite> cipherSuites(sk_SSL_CIPHER_num(ciphers));

    for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i)
    {
        auto cipher = sk_SSL_CIPHER_value(ciphers, i);
        assert(cipher != nullptr);

        cipherSuites[i] = ::CreateCipherSuite(cipher);
    }

    if (supported)
        sk_SSL_CIPHER_free(ciphers);

    return cipherSuites;
}

EvpMacPtr CipherSuiteManager::fetchMac(std::string_view algorithm)
{
    auto mac = EvpMacPtr(EVP_MAC_fetch(nullptr, algorithm.data(), nullptr));
    tls::ThrowIfTrue(mac == nullptr);
    return mac;
}

EvpKdfPtr CipherSuiteManager::fetchKdf(std::string_view algorithm)
{
    auto kdf = EvpKdfPtr(EVP_KDF_fetch(nullptr, algorithm.data(), nullptr));
    tls::ThrowIfTrue(kdf == nullptr);
    return kdf;
}

EvpMdPtr CipherSuiteManager::fetchDigest(std::string_view algorithm)
{
    auto digest = EvpMdPtr(EVP_MD_fetch(nullptr, algorithm.data(), nullptr));
    tls::ThrowIfTrue(digest == nullptr);
    return digest;
}

EvpCipherPtr CipherSuiteManager::fetchCipher(std::string_view algorithm)
{
    auto cipher = EvpCipherPtr(EVP_CIPHER_fetch(nullptr, algorithm.data(), nullptr));
    tls::ThrowIfTrue(cipher == nullptr);
    return cipher;
}

void CipherSuiteManager::setSecurityLevel(const int securityLevel)
{
    ThrowIfFalse(securityLevel >= 0 && securityLevel <= 5,
                 "Security level must be in range [0..5]");
    SSL_set_security_level(impl_->ssl, securityLevel);
}

} // namespace snet::tls