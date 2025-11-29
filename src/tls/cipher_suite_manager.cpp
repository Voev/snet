#include <cassert>
#include <unordered_map>

#include <snet/tls/cipher_suite.hpp>
#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/crypto/exception.hpp>
#include <snet/crypto/pointers.hpp>

#include <casket/utils/load_store.hpp>

using namespace casket;
using namespace snet::crypto;

namespace snet::tls
{

static std::unordered_map<uint16_t, CipherSuiteMeta> gCipherSuiteMeta = {
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

struct CipherSuiteManager::Impl final
{
public:
    Impl()
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

void CipherSuiteManager::setVersion(const ProtocolVersion& version)
{
    crypto::ThrowIfFalse(SSL_set_min_proto_version(impl_->ssl, static_cast<int>(version.code())));
    crypto::ThrowIfFalse(SSL_set_max_proto_version(impl_->ssl, static_cast<int>(version.code())));
}

void CipherSuiteManager::setSecurityLevel(const int securityLevel)
{
    crypto::ThrowIfFalse(securityLevel >= 0 && securityLevel <= 5, "Security level must be in range [0..5]");
    SSL_set_security_level(impl_->ssl, securityLevel);
}

int CipherSuiteManager::getTagLengthByID(std::uint16_t id)
{
    auto meta = gCipherSuiteMeta.find(id);
    return meta != gCipherSuiteMeta.end() ? meta->second.cipherTagLength : 0;
}

} // namespace snet::tls