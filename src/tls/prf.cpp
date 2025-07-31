#include <algorithm>
#include <cstring>
#include <limits>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/crypto_manager.hpp>

#include <snet/tls/prf.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

#include <casket/utils/load_store.hpp>

#include <openssl/kdf.h>
#include <openssl/core_names.h>

using namespace snet::crypto;

namespace snet::tls
{

void ssl3Prf(const Secret& secret, nonstd::span<const uint8_t> clientRandom, nonstd::span<const uint8_t> serverRandom,
             nonstd::span<uint8_t> out)
{
    unsigned int ch = 'A';
    unsigned char salt[EVP_MAX_MD_SIZE];
    unsigned char buffer[EVP_MAX_MD_SIZE];
    unsigned int n, saltSize;

    auto md5 = crypto::CryptoManager::getInstance().fetchDigest("MD5");
    const auto md5Length = EVP_MD_get_size(md5);

    auto sha1 = crypto::CryptoManager::getInstance().fetchDigest("SHA1");

    HashCtxPtr ctx(EVP_MD_CTX_new());
    crypto::ThrowIfTrue(ctx == nullptr);

    saltSize = 0;
    nonstd::span<uint8_t> block = out;

    for (size_t i = 0; i < out.size(); i += md5Length)
    {
        saltSize++;
        ThrowIfTrue(saltSize > sizeof(salt), "salt buffer too small");
        std::memset(salt, ch, saltSize);
        ch++;

        crypto::ThrowIfFalse(0 < EVP_DigestInit_ex(ctx, sha1, nullptr));
        crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, salt, saltSize));
        crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, secret.data(), secret.size()));
        crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, clientRandom.data(), clientRandom.size()));
        crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, serverRandom.data(), serverRandom.size()));
        crypto::ThrowIfFalse(0 < EVP_DigestFinal_ex(ctx, buffer, &n));

        crypto::ThrowIfFalse(0 < EVP_DigestInit_ex(ctx, md5, nullptr));
        crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, secret.data(), secret.size()));
        crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, buffer, n));

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

void tls1Prf(std::string_view algorithm, const Secret& secret, std::string_view label,
             nonstd::span<const uint8_t> clientRandom, nonstd::span<const uint8_t> serverRandom,
             nonstd::span<uint8_t> out)
{
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
}

void HkdfExpand(std::string_view algorithm, nonstd::span<const uint8_t> secret, nonstd::span<const uint8_t> label,
                nonstd::span<const uint8_t> data, nonstd::span<uint8_t> out)
{
    static int mode{EVP_KDF_HKDF_MODE_EXPAND_ONLY};
    static constexpr std::array<uint8_t, 6> labelPrefix = {0x74, 0x6C, 0x73, 0x31, 0x33, 0x20};

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