/// @file
/// @brief Implementation of the CipherSuiteManager class.

#include <snet/tls/cipher_suite_manager.hpp>

#include <algorithm>
#include <cassert>
#include <unordered_map>

#include <openssl/ssl.h>

#include <casket/utils/load_store.hpp>

#include <snet/crypto/exception.hpp>

using namespace casket;
using namespace snet::crypto;

namespace snet::tls
{

namespace
{

/// @brief Extract the wire ID from an SSL_CIPHER.
///
/// OpenSSL 3.x: SSL_CIPHER_get_protocol_id returns the 16-bit wire ID.
/// OpenSSL 1.1.1: SSL_CIPHER_get_id returns a 24-bit value where the low
/// 16 bits are the wire ID.
std::uint16_t cipherWireId(const SSL_CIPHER* cs) noexcept
{
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    return static_cast<std::uint16_t>(SSL_CIPHER_get_protocol_id(cs));
#else
    return static_cast<std::uint16_t>(SSL_CIPHER_get_id(cs) & 0xFFFF);
#endif
}

/// @brief AEAD tag lengths for known cipher suites.
const std::unordered_map<std::uint16_t, CipherSuiteMeta> kCipherSuiteMeta = {
    {make_uint16(0x13, 0x01), {EVP_GCM_TLS_TAG_LEN}},        {make_uint16(0x13, 0x02), {EVP_GCM_TLS_TAG_LEN}},
    {make_uint16(0x13, 0x03), {EVP_CHACHAPOLY_TLS_TAG_LEN}}, {make_uint16(0x13, 0x04), {EVP_CCM_TLS_TAG_LEN}},
    {make_uint16(0x13, 0x05), {EVP_CCM8_TLS_TAG_LEN}},       {make_uint16(0xC0, 0x9C), {EVP_CCM_TLS_TAG_LEN}},
    {make_uint16(0xC0, 0x9D), {EVP_CCM_TLS_TAG_LEN}},        {make_uint16(0xC0, 0x9E), {EVP_CCM_TLS_TAG_LEN}},
    {make_uint16(0xC0, 0x9F), {EVP_CCM_TLS_TAG_LEN}},        {make_uint16(0xC0, 0xA0), {EVP_CCM8_TLS_TAG_LEN}},
    {make_uint16(0xC0, 0xA1), {EVP_CCM8_TLS_TAG_LEN}},       {make_uint16(0xC0, 0xA2), {EVP_CCM8_TLS_TAG_LEN}},
    {make_uint16(0xC0, 0xA3), {EVP_CCM8_TLS_TAG_LEN}},       {make_uint16(0xC0, 0xA4), {EVP_CCM_TLS_TAG_LEN}},
    {make_uint16(0xC0, 0xA5), {EVP_CCM_TLS_TAG_LEN}},        {make_uint16(0xC0, 0xA6), {EVP_CCM_TLS_TAG_LEN}},
    {make_uint16(0xC0, 0xA7), {EVP_CCM_TLS_TAG_LEN}},        {make_uint16(0xC0, 0xA8), {EVP_CCM8_TLS_TAG_LEN}},
    {make_uint16(0xC0, 0xA9), {EVP_CCM8_TLS_TAG_LEN}},       {make_uint16(0xC0, 0xAA), {EVP_CCM8_TLS_TAG_LEN}},
    {make_uint16(0xC0, 0xAB), {EVP_CCM8_TLS_TAG_LEN}},       {make_uint16(0xC0, 0xAC), {EVP_CCM_TLS_TAG_LEN}},
    {make_uint16(0xC0, 0xAD), {EVP_CCM_TLS_TAG_LEN}},        {make_uint16(0xC0, 0xAE), {EVP_CCM8_TLS_TAG_LEN}},
    {make_uint16(0xC0, 0xAF), {EVP_CCM8_TLS_TAG_LEN}},       {make_uint16(0xC0, 0xB2), {EVP_CCM_TLS_TAG_LEN}},
    {make_uint16(0xC0, 0xB3), {EVP_CCM_TLS_TAG_LEN}},
};

} // namespace

// ─────────────────────────── Impl ───────────────────────────

struct CipherSuiteManager::Impl final
{
    explicit Impl()
        : ctx(SSL_CTX_new(TLS_method()))
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

    /// @brief Fill supportedCache_ from OpenSSL if not already valid.
    void ensureSupportedCache()
    {
        if (supportedCacheValid_)
            return;

        supportedCache_.clear();

        STACK_OF(SSL_CIPHER)* ciphers = SSL_get1_supported_ciphers(ssl);
        crypto::ThrowIfTrue(ciphers == nullptr, "Failed to get supported cipher suites");

        const int n = sk_SSL_CIPHER_num(ciphers);
        supportedCache_.reserve(static_cast<std::size_t>(n));

        for (int i = 0; i < n; ++i)
            supportedCache_.push_back(sk_SSL_CIPHER_value(ciphers, i));

        sk_SSL_CIPHER_free(ciphers);
        supportedCacheValid_ = true;
    }

    /// @brief Invalidate the cache after a configuration change.
    void invalidateSupportedCache() noexcept
    {
        supportedCache_.clear();
        supportedCacheValid_ = false;
    }

    SSL_CTX* ctx;
    SSL* ssl;

    std::vector<const CipherSuite*> supportedCache_;
    bool supportedCacheValid_ = false;
};

// ─────────────────────────── CipherSuiteManager ───────────────────────────

CipherSuiteManager::CipherSuiteManager()
    : impl_(std::make_unique<Impl>())
{
}

CipherSuiteManager::~CipherSuiteManager() noexcept = default;

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
    if (supported)
    {
        impl_->ensureSupportedCache();
        return impl_->supportedCache_; // copy; use getSupportedCipherSuites() for a view
    }

    STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(impl_->ssl);
    crypto::ThrowIfTrue(ciphers != nullptr, "Failed to get cipher suites");

    const int n = sk_SSL_CIPHER_num(ciphers);
    std::vector<const CipherSuite*> cipherSuites(static_cast<std::size_t>(n));

    for (int i = 0; i < n; ++i)
        cipherSuites[static_cast<std::size_t>(i)] = sk_SSL_CIPHER_value(ciphers, i);

    return cipherSuites;
}

nonstd::span<const CipherSuite*> CipherSuiteManager::getSupportedCipherSuites()
{
    impl_->ensureSupportedCache();
    return {impl_->supportedCache_.data(), impl_->supportedCache_.size()};
}

void CipherSuiteManager::setVersion(const ProtocolVersion& version)
{
    crypto::ThrowIfFalse(SSL_set_min_proto_version(impl_->ssl, static_cast<int>(version.code())));
    crypto::ThrowIfFalse(SSL_set_max_proto_version(impl_->ssl, static_cast<int>(version.code())));
    impl_->invalidateSupportedCache();
}

void CipherSuiteManager::setSecurityLevel(const int securityLevel)
{
    crypto::ThrowIfFalse(securityLevel >= 0 && securityLevel <= 5, "Security level must be in range [0..5]");
    SSL_set_security_level(impl_->ssl, securityLevel);
    impl_->invalidateSupportedCache();
}

int CipherSuiteManager::getTagLengthByID(std::uint16_t id)
{
    auto it = kCipherSuiteMeta.find(id);
    return it != kCipherSuiteMeta.end() ? it->second.cipherTagLength : 0;
}

bool CipherSuiteManager::isSupported(std::uint16_t id)
{
    impl_->ensureSupportedCache();

    for (auto* cs : impl_->supportedCache_)
    {
        if (cipherWireId(cs) == id)
            return true;
    }
    return false;
}

std::size_t CipherSuiteManager::filterSupported(nonstd::span<const std::uint16_t> ids, nonstd::span<std::uint16_t> out)
{
    impl_->ensureSupportedCache();

    std::size_t n = 0;
    for (auto id : ids)
    {
        if (n == out.size())
            break;

        for (auto* cs : impl_->supportedCache_)
        {
            if (cipherWireId(cs) == id)
            {
                out[n++] = id;
                break;
            }
        }
    }
    return n;
}

} // namespace snet::tls