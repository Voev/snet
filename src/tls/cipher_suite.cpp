#include <snet/tls/cipher_suite.hpp>
#include <openssl/ssl.h>
#include <snet/tls/exception.hpp>
#include <snet/utils/endianness.hpp>
#include <snet/utils/exception.hpp>

using namespace snet::tls;

namespace
{

static KexAlg GetKexAlg(const SSL_CIPHER* cipher)
{
    switch (SSL_CIPHER_get_kx_nid(cipher))
    {
    case NID_kx_any:
        return KexAlg::Any;
    case NID_kx_srp:
        return KexAlg::SRP;
    case NID_kx_psk:
        return KexAlg::PSK;
    case NID_kx_rsa:
        return KexAlg::RSA;
    case NID_kx_rsa_psk:
        return KexAlg::RSA_PSK;
    case NID_kx_dhe:
        return KexAlg::DHE;
    case NID_kx_dhe_psk:
        return KexAlg::DHE_PSK;
    case NID_kx_ecdhe:
        return KexAlg::ECDHE;
    case NID_kx_ecdhe_psk:
        return KexAlg::ECDHE_PSK;
    case NID_kx_gost:
        return KexAlg::GOST;
    case NID_kx_gost18:
        return KexAlg::GOST18;

    default:;
    }
    return KexAlg::Unknown;
}

static AuthAlg GetAuthAlg(const SSL_CIPHER* cipher)
{
    switch (SSL_CIPHER_get_auth_nid(cipher))
    {
    case NID_auth_null:
        return AuthAlg::Null;
    case NID_auth_any:
        return AuthAlg::Any;
    case NID_auth_psk:
        return AuthAlg::PSK;
    case NID_auth_srp:
        return AuthAlg::SRP;
    case NID_auth_rsa:
        return AuthAlg::RSA;
    case NID_auth_dss:
        return AuthAlg::DSS;
    case NID_auth_ecdsa:
        return AuthAlg::ECDSA;
    case NID_auth_gost01:
        return AuthAlg::GOST_2001;
    case NID_auth_gost12:
        return AuthAlg::GOST_2012;
    default:;
    }
    return AuthAlg::Unknown;
}

} // namespace

namespace snet::tls
{

CipherSuite::CipherSuite()
    : name_()
    , id_(0)
    , strengthBits_(0)
    , algBits_(0)
    , kex_(KexAlg::Unknown)
    , auth_(AuthAlg::Unknown)
    , aead_(false)
{
}

CipherSuite::~CipherSuite() noexcept
{
}

CipherSuite::CipherSuite(std::string name, std::uint32_t id, std::uint32_t strengthBits,
                         std::uint32_t algBits, KexAlg kex, AuthAlg auth, std::string cipher,
                         std::string digest, std::string handshakeDigest, bool aead)
    : name_(std::move(name))
    , id_(id)
    , strengthBits_(strengthBits)
    , algBits_(algBits)
    , kex_(kex)
    , auth_(auth)
    , cipher_(std::move(cipher))
    , digest_(std::move(digest))
    , handshakeDigest_(std::move(handshakeDigest))
    , aead_(aead)
{
}

const std::string& CipherSuite::name() const
{
    return name_;
}

std::uint32_t CipherSuite::id() const
{
    return id_;
}

KexAlg CipherSuite::getKeyExchAlg() const
{
    return kex_;
}

AuthAlg CipherSuite::getAuthAlg() const
{
    return auth_;
}

const std::string& CipherSuite::getDigestName() const
{
    return digest_;
}

const std::string& CipherSuite::getHandshakeDigest() const
{
    return handshakeDigest_;
}

const std::string& CipherSuite::getCipherName() const
{
    return cipher_;
}

std::uint32_t CipherSuite::getStrengthBits() const
{
    return strengthBits_;
}

std::uint32_t CipherSuite::getAlgBits() const
{
    return algBits_;
}

bool CipherSuite::isAEAD() const
{
    return aead_;
}

struct CipherSuiteManager::Impl final
{
public:
    Impl()
        : ctx(SSL_CTX_new(TLS_client_method()))
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

CipherSuite CipherSuiteManager::getCipherSuiteById(uint32_t id)
{
    uint32_t bytes = utils::host_to_be(id);
    uint8_t* ptr = reinterpret_cast<uint8_t*>(&bytes);
    ptr += 2;

    auto cipherSuite = SSL_CIPHER_find(impl_->ssl, ptr);
    if (cipherSuite != nullptr)
    {
        std::uint32_t id = SSL_CIPHER_get_id(cipherSuite);
        std::string name = SSL_CIPHER_get_name(cipherSuite);
        auto kex = GetKexAlg(cipherSuite);
        auto auth = GetAuthAlg(cipherSuite);
        auto cipher = OBJ_nid2sn(SSL_CIPHER_get_cipher_nid(cipherSuite));
        auto digest = OBJ_nid2sn(SSL_CIPHER_get_digest_nid(cipherSuite));
        auto handshakeDigest = EVP_MD_get0_name(SSL_CIPHER_get_handshake_digest(cipherSuite));
        int algBits{0};
        int strengthBits = SSL_CIPHER_get_bits(cipherSuite, &algBits);
        return CipherSuite(name, id, strengthBits, algBits, kex, auth, cipher, digest,
                           handshakeDigest, SSL_CIPHER_is_aead(cipherSuite));
    }
    return CipherSuite();
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

} // namespace snet::tls
