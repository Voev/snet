#include <unordered_map>

#include <snet/tls/group_params.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

#include <openssl/evp.h>
#include <openssl/core_names.h>

namespace snet::tls
{

struct GroupParamInfo
{
    const char* algorithm{nullptr};
    const char* groupName{nullptr};
};

static std::unordered_map<GroupParamsCode, GroupParamInfo> gGroupParams{
    {GroupParams::SECP256R1, {"EC", SN_secp256k1}}, {GroupParams::SECP384R1, {"EC", SN_secp384r1}},
    {GroupParams::SECP521R1, {"EC", SN_secp521r1}}, {GroupParams::X25519, {"X25519", nullptr}},
    {GroupParams::X448, {"X448", nullptr}},
};

/*
static const OSSL_PARAM param_group_list[][10] = {
    TLS_GROUP_ENTRY("K-163", "sect163k1", "EC", 0),
    TLS_GROUP_ENTRY("sect163r1", "sect163r1", "EC", 1),
    TLS_GROUP_ENTRY("B-163", "sect163r2", "EC", 2),
    TLS_GROUP_ENTRY("sect193r1", "sect193r1", "EC", 3),
    TLS_GROUP_ENTRY("sect193r2", "sect193r2", "EC", 4),
    TLS_GROUP_ENTRY("K-233", "sect233k1", "EC", 5),
    TLS_GROUP_ENTRY("B-233", "sect233r1", "EC", 6),
    TLS_GROUP_ENTRY("sect239k1", "sect239k1", "EC", 7),
    TLS_GROUP_ENTRY("sect283k1", "sect283k1", "EC", 8),
    TLS_GROUP_ENTRY("K-283", "sect283k1", "EC", 8),
    TLS_GROUP_ENTRY("sect283r1", "sect283r1", "EC", 9),
    TLS_GROUP_ENTRY("B-283", "sect283r1", "EC", 9),
    TLS_GROUP_ENTRY("sect409k1", "sect409k1", "EC", 10),
    TLS_GROUP_ENTRY("K-409", "sect409k1", "EC", 10),
    TLS_GROUP_ENTRY("B-409", "sect409r1", "EC", 11),
    TLS_GROUP_ENTRY("K-571", "sect571k1", "EC", 12),
    TLS_GROUP_ENTRY("B-571", "sect571r1", "EC", 13),

    TLS_GROUP_ENTRY("secp160k1", "secp160k1", "EC", 14),
    TLS_GROUP_ENTRY("secp160r1", "secp160r1", "EC", 15),
    TLS_GROUP_ENTRY("secp160r2", "secp160r2", "EC", 16),
    TLS_GROUP_ENTRY("secp192k1", "secp192k1", "EC", 17),
    TLS_GROUP_ENTRY("secp192r1", "prime192v1", "EC", 18),
    TLS_GROUP_ENTRY("P-192", "prime192v1", "EC", 18),
    TLS_GROUP_ENTRY("secp224k1", "secp224k1", "EC", 19),
    TLS_GROUP_ENTRY("secp224r1", "secp224r1", "EC", 20),
    TLS_GROUP_ENTRY("P-224", "secp224r1", "EC", 20),
    TLS_GROUP_ENTRY("secp256k1", "secp256k1", "EC", 21),
    TLS_GROUP_ENTRY("secp256r1", "prime256v1", "EC", 22),
    TLS_GROUP_ENTRY("P-256", "prime256v1", "EC", 22),
    TLS_GROUP_ENTRY("secp384r1", "secp384r1", "EC", 23),
    TLS_GROUP_ENTRY("P-384", "secp384r1", "EC", 23),
    TLS_GROUP_ENTRY("secp521r1", "secp521r1", "EC", 24),
    TLS_GROUP_ENTRY("P-521", "secp521r1", "EC", 24),

    TLS_GROUP_ENTRY("brainpoolP256r1", "brainpoolP256r1", "EC", 25),
    TLS_GROUP_ENTRY("brainpoolP384r1", "brainpoolP384r1", "EC", 26),
    TLS_GROUP_ENTRY("brainpoolP512r1", "brainpoolP512r1", "EC", 27),

    TLS_GROUP_ENTRY("x25519", "X25519", "X25519", 28),
    TLS_GROUP_ENTRY("x448", "X448", "X448", 29),

    TLS_GROUP_ENTRY("ffdhe2048", "ffdhe2048", "DH", 30),
    TLS_GROUP_ENTRY("ffdhe3072", "ffdhe3072", "DH", 31),
    TLS_GROUP_ENTRY("ffdhe4096", "ffdhe4096", "DH", 32),
    TLS_GROUP_ENTRY("ffdhe6144", "ffdhe6144", "DH", 33),
    TLS_GROUP_ENTRY("ffdhe8192", "ffdhe8192", "DH", 34),
*/
const char* GroupParams::toString() const
{
    switch (m_code)
    {
    case GroupParams::SECP256R1:
        return "prime256v1"; // P-256
    case GroupParams::SECP384R1:
        return "secp384r1"; // P-384
    case GroupParams::SECP521R1:
        return "secp521r1"; // P-521
    case GroupParams::BRAINPOOL256R1:
        return "brainpoolP256r1";
    case GroupParams::BRAINPOOL384R1:
        return "brainpoolP384r1";
    case GroupParams::BRAINPOOL512R1:
        return "brainpoolP512r1";
    case GroupParams::X25519:
        return "X25519";
    case GroupParams::X448:
        return "X448";

    case GroupParams::FFDHE_2048:
        return "ffdhe2048";
    case GroupParams::FFDHE_3072:
        return "ffdhe3072";
    case GroupParams::FFDHE_4096:
        return "ffdhe4096";
    case GroupParams::FFDHE_6144:
        return "ffdhe6144";
    case GroupParams::FFDHE_8192:
        return "ffdhe8192";

    default:
        return nullptr;
    }
}

crypto::KeyPtr GenerateKeyByGroupParams(const GroupParams groupParams)
{
    auto param = gGroupParams.find(groupParams.code());
    if (param == gGroupParams.end())
    {
        return nullptr;
    }

    auto ctx = CipherSuiteManager::getInstance().createKeyContext(param->second.algorithm);
    crypto::ThrowIfFalse(0 < EVP_PKEY_keygen_init(ctx));

    if (groupParams.is_ecdh_named_curve())
    {
        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_group_name(ctx, param->second.groupName));
    }

    Key* pkey{nullptr};
    crypto::ThrowIfFalse(0 < EVP_PKEY_generate(ctx, &pkey));
    return crypto::KeyPtr{pkey};
}

crypto::KeyPtr GenerateGroupParams(const GroupParams groupParams)
{
    auto param = gGroupParams.find(groupParams.code());
    if (param == gGroupParams.end())
    {
        return nullptr;
    }

    auto ctx = CipherSuiteManager::getInstance().createKeyContext(param->second.algorithm);
    crypto::ThrowIfFalse(0 < EVP_PKEY_paramgen_init(ctx));

    if (groupParams.is_ecdh_named_curve())
    {
        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_group_name(ctx, param->second.groupName));
    }

    Key* params{nullptr};
    crypto::ThrowIfFalse(0 < EVP_PKEY_paramgen(ctx, &params));
    return crypto::KeyPtr{params};
}

} // namespace snet::tls