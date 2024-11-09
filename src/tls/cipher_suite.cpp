#include <snet/tls/cipher_suite.hpp>
#include <openssl/ssl.h>
#include <snet/tls/exception.hpp>
#include <snet/utils/endianness.hpp>
#include <snet/utils/exception.hpp>

using namespace snet::tls;

namespace {

static KexAlg GetKexAlg(const SSL_CIPHER* cipher) {
    switch (SSL_CIPHER_get_kx_nid(cipher)) {
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

static AuthAlg GetAuthAlg(const SSL_CIPHER* cipher) {
    switch (SSL_CIPHER_get_auth_nid(cipher)) {
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

static EncAlg OpenSSLEncAlg2CustomEncAlg(const int nid) {
    switch (nid) { 
        case NID_aes_128_cbc:
            return EncAlg::AES_128_CBC;
        case NID_aes_256_cbc:
            return EncAlg::AES_256_CBC;
        case NID_aes_128_gcm:
            return EncAlg::AES_128_GCM;
        case NID_aes_256_gcm:
            return EncAlg::AES_256_GCM;
        default:; 
    }
    return EncAlg::Unknown;
}

static int CustomEncAlg2OpenSSLEncAlg(const EncAlg alg) {
    switch (alg) { 
        case EncAlg::AES_128_CBC:
            return NID_aes_128_cbc;
        case EncAlg::AES_256_CBC:
            return NID_aes_256_cbc;
        case EncAlg::AES_128_GCM:
            return NID_aes_128_gcm;
        case  EncAlg::AES_256_GCM:
            return NID_aes_256_gcm;
        default:; 
    }
    return NID_undef;
}

static int CustomMacAlg2OpenSSLMacAlg(const MACAlg alg)
{
    switch (alg) {
        case MACAlg::MD5:
            return NID_md5;
        case MACAlg::SHA1:
            return NID_sha1;
        case MACAlg::SHA256:
            return NID_sha256;
        case MACAlg::SHA384:
            return NID_sha384;
        case MACAlg::GOST_28147:
            return NID_id_Gost28147_89_MAC;
        case MACAlg::GOST_28147_12:
            return NID_gost_mac_12;
        case MACAlg::GOST_R3411_94:
            return NID_id_GostR3411_94;
        case MACAlg::GOST_R3411_2012_256:
            return NID_id_GostR3411_2012_256;
        case MACAlg::GOST_R3411_2012_512:
            return NID_id_GostR3411_2012_512;
        case MACAlg::GOST_Magma:
            return NID_magma_mac;
        case MACAlg::GOST_Kuznyechik:
            return NID_kuznyechik_mac;
        default:;
    }
    return NID_undef;
}

static MACAlg GetMacAlg(const int nid) {
    switch (nid) {
        case NID_md5:
            return MACAlg::MD5;
        case NID_sha1:
            return MACAlg::SHA1;
        case NID_sha256:
            return MACAlg::SHA256;
        case NID_sha384:
            return MACAlg::SHA384;
        case NID_id_Gost28147_89_MAC:
            return MACAlg::GOST_28147;
        case NID_gost_mac_12:
            return MACAlg::GOST_28147_12;
        case NID_id_GostR3411_94:
            return MACAlg::GOST_R3411_94;
        case NID_id_GostR3411_2012_256:
            return MACAlg::GOST_R3411_2012_256;
        case NID_id_GostR3411_2012_512:
            return MACAlg::GOST_R3411_2012_512;
        case NID_magma_mac:
            return MACAlg::GOST_Magma;
        case NID_kuznyechik_mac:
            return MACAlg::GOST_Kuznyechik;
        default:;
    }
    return MACAlg::Unknown;
}

} // namespace

namespace snet::tls {

const EVP_MD* GetMacAlgorithm(const MACAlg alg) {
    auto nid = ::CustomMacAlg2OpenSSLMacAlg(alg);
    return (nid == NID_undef ? EVP_md_null() : EVP_get_digestbynid(nid));
}

const EVP_CIPHER* GetEncAlgorithm(const EncAlg alg) {
    auto nid = ::CustomEncAlg2OpenSSLEncAlg(alg);
    return (nid == NID_undef ? EVP_enc_null() : EVP_get_cipherbynid(nid));
}

CipherSuite::CipherSuite()
    : name_()
    , id_(0)
    , strengthBits_(0)
    , algBits_(0)
    , kex_(KexAlg::Unknown)
    , auth_(AuthAlg::Unknown)
    , enc_(EncAlg::Unknown)
    , mac_(MACAlg::Unknown)
    , aead_(false) {
}

CipherSuite::~CipherSuite() noexcept {
}

CipherSuite::CipherSuite(
    std::string name, std::uint32_t id, std::uint32_t strengthBits, std::uint32_t algBits, KexAlg kex, AuthAlg auth,
    EncAlg enc, MACAlg mac, bool aead)
    : name_(std::move(name))
    , id_(id)
    , strengthBits_(strengthBits)
    , algBits_(algBits)
    , kex_(kex)
    , auth_(auth)
    , enc_(enc)
    , mac_(mac)
    , aead_(aead) {
}

KexAlg CipherSuite::getKeyExchAlg() const {
    return kex_;
}

AuthAlg CipherSuite::getAuthAlg() const {
    return auth_;
}

MACAlg CipherSuite::getHashAlg() const {
    return mac_;
}

EncAlg CipherSuite::getEncAlg() const {
    return enc_;
}

std::uint32_t CipherSuite::getStrengthBits() const {
    return strengthBits_;
}

std::uint32_t CipherSuite::getAlgBits() const {
    return algBits_;
}

bool CipherSuite::isAEAD() const
{
    return aead_;
}

std::uint32_t CipherSuite::getAeadTagLength() const
{
    utils::ThrowIfFalse(isAEAD(), "must be AEAD cipher");

    if (enc_ == EncAlg::AES_128_GCM || enc_ == EncAlg::AES_256_GCM)
        return EVP_GCM_TLS_TAG_LEN;
    else if (enc_ == EncAlg::CHACHA20_POLY1305)
        return EVP_CHACHAPOLY_TLS_TAG_LEN;
    else if (enc_ == EncAlg::AES_128_CCM)
        return EVP_CCM_TLS_TAG_LEN;
    else if (enc_ == EncAlg::AES_128_CCM_8)
        return EVP_CCM8_TLS_TAG_LEN;

    return 0U;
}

struct CipherSuiteManager::Impl final {
public:
    Impl()
        : ctx(SSL_CTX_new(TLS_client_method()))
        , ssl(nullptr) {
        tls::ThrowIfFalse(ctx != nullptr);

        ssl = SSL_new(ctx);
        tls::ThrowIfFalse(ssl != nullptr);
    }

    ~Impl() noexcept {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
    }

    SSL_CTX* ctx;
    SSL* ssl;
};

CipherSuiteManager::CipherSuiteManager()
    : impl_(std::make_unique<Impl>()) {
}

CipherSuiteManager::~CipherSuiteManager() noexcept {
}

CipherSuite CipherSuiteManager::getCipherSuiteById(uint32_t id) {
    uint32_t bytes = utils::host_to_be(id);
    uint8_t* ptr = reinterpret_cast<uint8_t*>(&bytes);
    ptr += 2;

    auto cipherSuite = SSL_CIPHER_find(impl_->ssl, ptr);
    if (cipherSuite != nullptr) {
        std::uint32_t id = SSL_CIPHER_get_id(cipherSuite);
        std::string name = SSL_CIPHER_get_name(cipherSuite);
        auto kex = GetKexAlg(cipherSuite);
        auto auth = GetAuthAlg(cipherSuite);
        auto enc = ::OpenSSLEncAlg2CustomEncAlg(SSL_CIPHER_get_cipher_nid(cipherSuite));
        auto mac = GetMacAlg(EVP_MD_type(SSL_CIPHER_get_handshake_digest(cipherSuite)));
        int algBits{0};
        int strengthBits = SSL_CIPHER_get_bits(cipherSuite, &algBits);
        return CipherSuite(name, id, strengthBits, algBits, kex, auth, enc, mac, SSL_CIPHER_is_aead(cipherSuite));
    }
    return CipherSuite();
}

} // namespace snet::tls
