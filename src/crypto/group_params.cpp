#include <unordered_map>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#include <casket/utils/exception.hpp>

#include <snet/crypto/crypto_manager.hpp>
#include <snet/crypto/group_params.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/exception.hpp>

#include <snet/tls/cipher_suite_manager.hpp>

namespace snet::crypto
{

struct GroupParamInfo
{
    const char* algorithm{nullptr};
    const char* groupName{nullptr};
};

// clang-format off
static std::unordered_map<GroupParams::Code, GroupParamInfo> gGroupParams{
    {GroupParams::SECP256R1, {"EC", SN_secp256k1}},
    {GroupParams::SECP384R1, {"EC", SN_secp384r1}},
    {GroupParams::SECP521R1, {"EC", SN_secp521r1}},
    {GroupParams::BRAINPOOL256R1, {"EC", SN_brainpoolP256r1}},
    {GroupParams::BRAINPOOL384R1, {"EC", SN_brainpoolP384r1}},
    {GroupParams::BRAINPOOL512R1, {"EC", SN_brainpoolP512r1}},
    {GroupParams::X25519, {"X25519", nullptr}},
    {GroupParams::X448, {"X448", nullptr}},
    {GroupParams::FFDHE_2048, {"DH", SN_ffdhe2048}},
    {GroupParams::FFDHE_3072, {"DH", SN_ffdhe3072}},
    {GroupParams::FFDHE_4096, {"DH", SN_ffdhe4096}},
    {GroupParams::FFDHE_6144, {"DH", SN_ffdhe6144}},
    {GroupParams::FFDHE_8192, {"DH", SN_ffdhe8192}},
};
// clang-format on

const std::vector<GroupParams>& GroupParams::getSupported()
{
    static std::vector<GroupParams> gSupportedGroups =
    {
        GroupParams(GroupParams::SECP256R1),
        GroupParams(GroupParams::SECP384R1),
        GroupParams(GroupParams::SECP521R1),
        GroupParams(GroupParams::BRAINPOOL256R1),
        GroupParams(GroupParams::BRAINPOOL384R1),
        GroupParams(GroupParams::BRAINPOOL512R1),
        GroupParams(GroupParams::X25519),
        GroupParams(GroupParams::X448),
    };
    return gSupportedGroups;
}

const char* GroupParams::toString() const
{
    switch (code_)
    {
    case GroupParams::Code::SECP256R1:
        return "prime256v1"; // P-256
    case GroupParams::Code::SECP384R1:
        return "secp384r1"; // P-384
    case GroupParams::Code::SECP521R1:
        return "secp521r1"; // P-521
    case GroupParams::Code::BRAINPOOL256R1:
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

KeyPtr GroupParams::generateParams(const GroupParams groupParams)
{
    auto param = gGroupParams.find(groupParams.code());
    casket::ThrowIfTrue(param == gGroupParams.end(), "Unsupported group parameters");

    auto ctx = CryptoManager::getInstance().createKeyContext(param->second.algorithm);
    ThrowIfFalse(0 < EVP_PKEY_paramgen_init(ctx));

    if (groupParams.isEcdhNamedCurve())
    {
        ThrowIfFalse(0 < EVP_PKEY_CTX_set_group_name(ctx, param->second.groupName));
    }

    Key* params{nullptr};
    ThrowIfFalse(0 < EVP_PKEY_paramgen(ctx, &params));
    return KeyPtr{params};
}

KeyPtr GroupParams::generateKeyByParams(const GroupParams groupParams)
{
    auto param = gGroupParams.find(groupParams.code());
    casket::ThrowIfTrue(param == gGroupParams.end(), "Unsupported group parameters");

    auto ctx = CryptoManager::getInstance().createKeyContext(param->second.algorithm);
    ThrowIfFalse(0 < EVP_PKEY_keygen_init(ctx));

    if (groupParams.isEcdhNamedCurve())
    {
        ThrowIfFalse(0 < EVP_PKEY_CTX_set_group_name(ctx, param->second.groupName));
    }

    Key* pkey{nullptr};
    ThrowIfFalse(0 < EVP_PKEY_keygen(ctx, &pkey));
    return KeyPtr{pkey};
}

KeyPtr GroupParams::generateKeyByParams(Key* params)
{
    Key* pkey{nullptr};
    auto ctx = CryptoManager::getInstance().createKeyContext(params);
    ThrowIfFalse(0 < EVP_PKEY_keygen_init(ctx));
    ThrowIfFalse(0 < EVP_PKEY_keygen(ctx, &pkey));
    return KeyPtr{pkey};
}

std::vector<uint8_t> GroupParams::deriveSecret(Key* privateKey, Key* publicKey, bool isTLSv3)
{
    size_t secretLength{0};

    auto ctx = CryptoManager::getInstance().createKeyContext(privateKey);
    crypto::ThrowIfFalse(0 < EVP_PKEY_derive_init(ctx));
    crypto::ThrowIfFalse(0 < EVP_PKEY_derive_set_peer(ctx, publicKey));
    crypto::ThrowIfFalse(0 < EVP_PKEY_derive(ctx, nullptr, &secretLength));
    
    if (isTLSv3 && EVP_PKEY_is_a(privateKey, "DH"))
    {
        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_dh_pad(ctx, 1));
    }
    
    std::vector<uint8_t> secret(secretLength);
    crypto::ThrowIfFalse(0 < EVP_PKEY_derive(ctx, secret.data(), &secretLength));

    secret.resize(secretLength);
    return secret;
}

} // namespace snet::crypto