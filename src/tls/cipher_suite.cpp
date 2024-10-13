#include <snet/tls/cipher_suite.hpp>
#include <snet/tls/settings.hpp>
#include <snet/tls/connection.hpp>
#include <openssl/ssl.h>

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

static EncAlg GetEncAlg(const SSL_CIPHER* cipher)
{
    switch (SSL_CIPHER_get_cipher_nid(cipher))
    {
    default:;
    }
    return EncAlg::SSL_SYM_Unknown;
}

static MACAlg GetMacAlg(const SSL_CIPHER* cipher)
{
    switch (SSL_CIPHER_get_digest_nid(cipher))
    {
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

namespace snet::tls
{

CipherSuite::CipherSuite()
    : name_()
    , id_(0)
    , strengthBits_(0)
    , algBits_(0)
    , kex_(KexAlg::Unknown)
    , auth_(AuthAlg::Unknown)
    , enc_(EncAlg::SSL_SYM_Unknown)
    , mac_(MACAlg::Unknown)
{
}

CipherSuite::~CipherSuite() noexcept
{
}

CipherSuite::CipherSuite(std::string name, std::uint32_t id,
                         std::uint32_t strengthBits, std::uint32_t algBits,
                         KexAlg kex, AuthAlg auth, EncAlg enc, MACAlg mac)
    : name_(std::move(name))
    , id_(id)
    , strengthBits_(strengthBits)
    , algBits_(algBits)
    , kex_(kex)
    , auth_(auth)
    , enc_(enc)
    , mac_(mac)
{
}

KexAlg CipherSuite::getKeyExchAlg() const
{
    return kex_;
}

AuthAlg CipherSuite::getAuthAlg() const
{
    return auth_;
}

MACAlg CipherSuite::getHashAlg() const
{
    return mac_;
}

EncAlg CipherSuite::getEncAlg() const
{
    return enc_;
}

std::uint32_t CipherSuite::getStrengthBits() const
{
    return strengthBits_;
}

std::uint32_t CipherSuite::getAlgBits() const
{
    return algBits_;
}

struct CipherSuiteManager::Impl final
{
public:
    Impl()
        : settings()
        , connection(settings)
    {
    }

    ~Impl() noexcept
    {
    }

    ClientSettings settings;
    Connection connection;
};

CipherSuiteManager::CipherSuiteManager()
    : impl_(std::make_unique<Impl>())
{
}

CipherSuiteManager::~CipherSuiteManager() noexcept
{
}

CipherSuite CipherSuiteManager::getCipherSuiteById(std::span<const uint8_t> id)
{
    auto cipherSuite = SSL_CIPHER_find(impl_->connection.ssl_, id.data());
    if (cipherSuite != nullptr)
    {
        std::uint32_t id = SSL_CIPHER_get_id(cipherSuite);
        std::string name = SSL_CIPHER_get_name(cipherSuite);
        auto kex = GetKexAlg(cipherSuite);
        auto auth = GetAuthAlg(cipherSuite);
        auto enc = GetEncAlg(cipherSuite);
        auto mac = GetMacAlg(cipherSuite);
        int algBits{0};
        int strengthBits = SSL_CIPHER_get_bits(cipherSuite, &algBits);
        return CipherSuite(name, id, strengthBits, algBits, kex, auth, enc,
                           mac);
    }
    return CipherSuite();
}

} // namespace snet::tls
