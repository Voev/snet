#include <algorithm>
#include <cstring>
#include <limits>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/crypto_manager.hpp>
#include <snet/crypto/hash_traits.hpp>
#include <snet/crypto/prf.hpp>

#include <casket/utils/load_store.hpp>

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#else
#include <openssl/evp.h>
#endif

namespace snet::crypto
{

void ssl3Prf(nonstd::span<const uint8_t> secret, nonstd::span<const uint8_t> clientRandom, nonstd::span<const uint8_t> serverRandom,
             nonstd::span<uint8_t> out)
{
    unsigned int ch = 'A';
    unsigned char salt[EVP_MAX_MD_SIZE];
    unsigned char buffer[EVP_MAX_MD_SIZE];
    unsigned int n, saltSize;

    auto md5 = crypto::CryptoManager::getInstance().fetchDigest("MD5");
    const auto md5Length = HashTraits::getSize(md5);

    auto sha1 = crypto::CryptoManager::getInstance().fetchDigest("SHA1");

    HashCtxPtr ctx = HashTraits::createContext();
    crypto::ThrowIfTrue(ctx == nullptr);

    saltSize = 0;
    nonstd::span<uint8_t> block = out;

    for (size_t i = 0; i < out.size(); i += md5Length)
    {
        saltSize++;
        ThrowIfTrue(saltSize > sizeof(salt), "salt buffer too small");
        std::memset(salt, ch, saltSize);
        ch++;

        HashTraits::initHash(ctx, sha1);
        HashTraits::updateHash(ctx, {salt, saltSize});
        HashTraits::updateHash(ctx, secret);
        HashTraits::updateHash(ctx, clientRandom);
        HashTraits::updateHash(ctx, serverRandom);
        crypto::ThrowIfFalse(0 < EVP_DigestFinal_ex(ctx, buffer, &n));

        HashTraits::initHash(ctx, md5);
        HashTraits::updateHash(ctx, secret);
        HashTraits::updateHash(ctx, {buffer, n});

        if (i + md5Length > out.size())
        {
            crypto::ThrowIfFalse(0 < EVP_DigestFinal_ex(ctx, buffer, &n));

            auto delta = out.size() - i;
            std::memcpy(block.data(), buffer, delta);
            block = block.subspan(delta);
        }
        else
        {
            crypto::ThrowIfFalse(0 < EVP_DigestFinal_ex(ctx, block.data(), &n));
            block = block.subspan(n);
        }
    }
}

void tls1Prf(std::string_view algorithm, nonstd::span<const uint8_t> secret, std::string_view label,
             nonstd::span<const uint8_t> clientRandom, nonstd::span<const uint8_t> serverRandom,
             nonstd::span<uint8_t> out)
{
#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)
    auto kdf = crypto::CryptoManager::getInstance().fetchKdf("TLS1-PRF");
    crypto::ThrowIfTrue(kdf == nullptr);

    KdfCtxPtr kctx(EVP_KDF_CTX_new(kdf));
    crypto::ThrowIfTrue(kctx == nullptr);

    OSSL_PARAM params[6], *p = params;
    *p++ =
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(algorithm.data()), algorithm.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, const_cast<uint8_t*>(secret.data()), secret.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, const_cast<char*>(label.data()), label.size());
    if (!clientRandom.empty())
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, const_cast<uint8_t*>(clientRandom.data()),
                                                 clientRandom.size());
    if (!serverRandom.empty())
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, const_cast<uint8_t*>(serverRandom.data()),
                                                 serverRandom.size());
    *p = OSSL_PARAM_construct_end();

    crypto::ThrowIfFalse(0 < EVP_KDF_derive(kctx, out.data(), out.size(), params));
#else
    auto digest = CryptoManager::getInstance().fetchDigest(algorithm);
    KeyCtxPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, nullptr));
    ThrowIfFalse(pctx, "failed to create key context (TLS1_PRF)");
    ThrowIfFalse(0 < EVP_PKEY_derive_init(pctx));
    ThrowIfFalse(0 < EVP_PKEY_CTX_set_tls1_prf_md(pctx, digest));
    ThrowIfFalse(0 < EVP_PKEY_CTX_set1_tls1_prf_secret(pctx, secret.data(), static_cast<int>(secret.size())));
    ThrowIfFalse(0 < EVP_PKEY_derive_init(pctx));
    ThrowIfFalse(0 < EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, label.data(), static_cast<int>(label.size())));
    ThrowIfFalse(0 < EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, clientRandom.data(), static_cast<int>(clientRandom.size())));
    ThrowIfFalse(0 < EVP_PKEY_CTX_add1_tls1_prf_seed(pctx, serverRandom.data(), static_cast<int>(serverRandom.size())));
    size_t outLength = out.size();
    ThrowIfFalse(0 < EVP_PKEY_derive(pctx, out.data(), &outLength));
#endif
}

static constexpr size_t kMaxFullLabelSize = 255;
static constexpr std::array<uint8_t, 6> labelPrefix = {0x74, 0x6C, 0x73, 0x31, 0x33, 0x20};

void HkdfExpand(std::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<const uint8_t> label,
                nonstd::span<const uint8_t> data, nonstd::span<uint8_t> out)
{

    ThrowIfFalse(labelPrefix.size() + label.size() <= kMaxFullLabelSize, "label too large");
    ThrowIfFalse(data.size() <= EVP_MAX_MD_SIZE, "context too large");
    ThrowIfFalse(out.size() <= std::numeric_limits<uint16_t>::max(), "invalid length");

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)

    static int mode{EVP_KDF_HKDF_MODE_EXPAND_ONLY};

    auto kdf = crypto::CryptoManager::getInstance().fetchKdf(OSSL_KDF_NAME_TLS1_3_KDF);

    KdfCtxPtr kctx(EVP_KDF_CTX_new(kdf));
    crypto::ThrowIfTrue(kctx == nullptr);

    OSSL_PARAM params[7], *p = params;
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(algorithm.data()), 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(secret.data()), secret.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX, const_cast<uint8_t*>(labelPrefix.data()),
                                             labelPrefix.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, const_cast<uint8_t*>(label.data()), label.size());

    if (!data.empty())
    {
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_DATA, const_cast<uint8_t*>(data.data()), data.size());
    }

    *p = OSSL_PARAM_construct_end();

    crypto::ThrowIfFalse(0 < EVP_KDF_derive(kctx, out.data(), out.size(), params));

#else
    static constexpr size_t maxHkdfLabelSize =
        sizeof(uint16_t) + 2 * sizeof(uint8_t) + kMaxFullLabelSize + EVP_MAX_MD_SIZE;

    std::array<uint8_t, maxHkdfLabelSize> hkdfLabel;
    uint8_t* ptr = hkdfLabel.data();

    // length (2 bytes)
    const auto len = static_cast<uint16_t>(out.size());
    *ptr++ = casket::get_byte<0>(len);
    *ptr++ = casket::get_byte<1>(len);

    // label length (1 byte)
    const size_t labelSize = labelPrefix.size() + label.size();
    *ptr++ = static_cast<uint8_t>(labelSize);

    // prefix + label
    std::memcpy(ptr, labelPrefix.data(), labelPrefix.size());
    ptr += labelPrefix.size();
    std::memcpy(ptr, label.data(), label.size());
    ptr += label.size();

    // context length (1 byte)
    *ptr++ = static_cast<uint8_t>(data.size());

    // context
    if (!data.empty())
    {
        memcpy(ptr, data.data(), data.size());
        ptr += data.size();
    }

    const size_t hkdfLabelSize = ptr - hkdfLabel.data();

    auto digest = CryptoManager::getInstance().fetchDigest(algorithm);
    KeyCtxPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    ThrowIfFalse(pctx, "failed to create key context (HKDF)");

    ThrowIfFalse(0 < EVP_PKEY_derive_init(pctx));
    ThrowIfFalse(0 < EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY));

    ThrowIfFalse(0 < EVP_PKEY_CTX_set_hkdf_md(pctx, digest));
    ThrowIfFalse(0 < EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.data(), static_cast<int>(secret.size())));
    ThrowIfFalse(0 < EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdfLabel.data(), static_cast<int>(hkdfLabelSize)));

    size_t outlen = out.size_bytes();
    ThrowIfFalse(0 < EVP_PKEY_derive(pctx, out.data(), &outlen));
#endif
}

void DeriveFinishedKey(std::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<uint8_t> out)
{
    static constexpr std::array<unsigned char, 8> finishedLabel = {0x66, 0x69, 0x6E, 0x69, 0x73, 0x68, 0x65, 0x64};

    HkdfExpand(algorithm, secret, finishedLabel, {}, out);
}

void DeriveKey(std::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<uint8_t> out)
{
    static constexpr std::array<unsigned char, 3> keyLabel = {0x6B, 0x65, 0x79};

    HkdfExpand(algorithm, secret, keyLabel, {}, out);
}

void DeriveIV(std::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<uint8_t> out)
{
    static constexpr std::array<unsigned char, 2> ivLabel = {0x69, 0x76};

    HkdfExpand(algorithm, secret, ivLabel, {}, out);
}

void UpdateTrafficSecret(std::string_view algorithm, nonstd::span<uint8_t> secret)
{
    static constexpr std::array<unsigned char, 11> trafficUpdateLabel = {0x74, 0x72, 0x61, 0x66, 0x66, 0x69,
                                                                         0x63, 0x20, 0x75, 0x70, 0x64};

    HkdfExpand(algorithm, secret, trafficUpdateLabel, {}, secret);
}

} // namespace snet::tls