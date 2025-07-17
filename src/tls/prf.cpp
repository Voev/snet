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

void HkdfExpand(std::string_view algorithm, const Secret& secret, nonstd::span<const uint8_t> label,
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

std::vector<uint8_t> hkdfExpandLabel(std::string_view algorithm, const Secret& secret, std::string_view label,
                                     nonstd::span<const uint8_t> context, const size_t length)
{
    // assemble (serialized) HkdfLabel
    std::vector<uint8_t> hkdfLabel;
    hkdfLabel.reserve(2 /* length */ + (label.size() + 6 /* 'tls13 ' */ + 1 /* length field*/) +
                      (context.size() + 1 /* length field*/));

    // length
    ThrowIfFalse(length <= std::numeric_limits<uint16_t>::max(), "invalid length");
    const auto len = static_cast<uint16_t>(length);
    hkdfLabel.push_back(casket::get_byte<0>(len));
    hkdfLabel.push_back(casket::get_byte<1>(len));

    // label
    const std::string prefix = "tls13 ";
    ThrowIfFalse(prefix.size() + label.size() <= 255, "label too large");
    hkdfLabel.push_back(static_cast<uint8_t>(prefix.size() + label.size()));
    hkdfLabel.insert(hkdfLabel.end(), prefix.cbegin(), prefix.cend());
    hkdfLabel.insert(hkdfLabel.end(), label.cbegin(), label.cend());

    // context
    ThrowIfFalse(context.size() <= 255, "context too large");
    hkdfLabel.push_back(static_cast<uint8_t>(context.size()));
    hkdfLabel.insert(hkdfLabel.end(), context.begin(), context.end());

    auto kdf = crypto::CryptoManager::getInstance().fetchKdf("HKDF");

    KdfCtxPtr kctx(EVP_KDF_CTX_new(kdf));
    crypto::ThrowIfTrue(kctx == nullptr);

    static int mode{EVP_KDF_HKDF_MODE_EXPAND_ONLY};
    OSSL_PARAM params[6], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(algorithm.data()), 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(secret.data()), secret.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(hkdfLabel.data()),
                                             hkdfLabel.size());
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p = OSSL_PARAM_construct_end();

    std::size_t outlen(length);
    std::vector<uint8_t> out(outlen);
    crypto::ThrowIfFalse(0 < EVP_KDF_derive(kctx, out.data(), out.size(), params));
    out.resize(outlen);

    return out;
}

} // namespace snet::tls