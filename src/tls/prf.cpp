#include <algorithm>
#include <cstring>
#include <limits>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/pointers.hpp>

#include <snet/tls/prf.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

#include <casket/utils/exception.hpp>
#include <snet/utils/load_store.hpp>

#include <openssl/kdf.h>
#include <openssl/core_names.h>

using namespace casket::utils;
using namespace snet::crypto;

namespace snet::tls
{

/* ASCII: "tls13 ", in hex for EBCDIC compatibility */
static const unsigned char gLabelPrefix[] = "\x74\x6C\x73\x31\x33\x20";

void ssl3Prf(const Secret& secret, std::span<const uint8_t> clientRandom, std::span<const uint8_t> serverRandom,
             std::span<uint8_t> out)
{
    static const unsigned char* salt[3] = {
        (const unsigned char*)"A",
        (const unsigned char*)"BB",
        (const unsigned char*)"CCC",
    };

    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int n;

    auto md5 = CipherSuiteManager::getInstance().fetchDigest("MD5");
    auto sha1 = CipherSuiteManager::getInstance().fetchDigest("SHA1");

    HashCtxPtr ctx(EVP_MD_CTX_new());
    crypto::ThrowIfTrue(ctx == nullptr);

    for (size_t i = 0; i < 3; ++i)
    {
        crypto::ThrowIfFalse(0 < EVP_DigestInit_ex(ctx, sha1, nullptr));
        crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, salt[i], strlen((const char*)salt[i])));
        crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, secret.data(), secret.size()));
        crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, clientRandom.data(), clientRandom.size()));
        crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, serverRandom.data(), serverRandom.size()));
        crypto::ThrowIfFalse(0 < EVP_DigestFinal_ex(ctx, buf, &n));
        crypto::ThrowIfFalse(0 < EVP_DigestInit_ex(ctx, md5, nullptr));
        crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, secret.data(), secret.size()));
        crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, buf, n));
        crypto::ThrowIfFalse(0 < EVP_DigestFinal_ex(ctx, out.data(), &n));

        out = out.subspan(n);
    }
}

void tls1Prf(std::string_view algorithm, const Secret& secret, std::string_view label,
             std::span<const uint8_t> clientRandom, std::span<const uint8_t> serverRandom, std::span<uint8_t> out)
{
    auto kdf = CipherSuiteManager::getInstance().fetchKdf("TLS1-PRF");
    crypto::ThrowIfTrue(kdf == nullptr);

    KdfCtxPtr kctx(EVP_KDF_CTX_new(kdf));
    crypto::ThrowIfTrue(kctx == nullptr);

    OSSL_PARAM params[6], *p = params;
    *p++ =
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(algorithm.data()), algorithm.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, const_cast<uint8_t*>(secret.data()), secret.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, const_cast<char*>(label.data()), label.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, const_cast<uint8_t*>(clientRandom.data()),
                                             clientRandom.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, const_cast<uint8_t*>(serverRandom.data()),
                                             serverRandom.size());
    *p = OSSL_PARAM_construct_end();

    crypto::ThrowIfFalse(0 < EVP_KDF_derive(kctx, out.data(), out.size(), params));
}

std::vector<uint8_t> DeriveSecret(std::string_view algorithm, const Secret& secret, std::string_view label,
                                  std::span<const uint8_t> context, const size_t length)
{
    // assemble (serialized) HkdfLabel
    std::vector<uint8_t> hkdfLabel;
    hkdfLabel.reserve(2 /* length */ + (label.size() + 6 /* 'tls13 ' */ + 1 /* length field*/) +
                      (context.size() + 1 /* length field*/));

    // length
    ThrowIfFalse(length <= std::numeric_limits<uint16_t>::max(), "invalid length");
    const auto len = static_cast<uint16_t>(length);
    hkdfLabel.push_back(utils::get_byte<0>(len));
    hkdfLabel.push_back(utils::get_byte<1>(len));

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

    auto kdf = CipherSuiteManager::getInstance().fetchKdf("HKDF");

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

std::vector<uint8_t> HkdfExtract(std::string_view algorithm, std::span<const uint8_t> prevSecret,
                                 std::span<const uint8_t> inSecret, size_t length)
{
    static int mode{EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY};
    static const char derived_secret_label[] = "derived";

    auto kdf = CipherSuiteManager::getInstance().fetchKdf(OSSL_KDF_NAME_TLS1_3_KDF);

    KdfCtxPtr kctx(EVP_KDF_CTX_new(kdf));
    crypto::ThrowIfTrue(kctx == nullptr);

    OSSL_PARAM params[7], *p = params;

    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, const_cast<char*>(algorithm.data()), 0);

    if (!inSecret.empty())
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (uint8_t*)inSecret.data(), inSecret.size());
    if (!prevSecret.empty())
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (uint8_t*)prevSecret.data(), prevSecret.size());

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX, (unsigned char*)gLabelPrefix,
                                             sizeof(gLabelPrefix) - 1);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, (unsigned char*)derived_secret_label,
                                             sizeof(derived_secret_label) - 1);
    *p++ = OSSL_PARAM_construct_end();

    std::vector<uint8_t> out(length);
    crypto::ThrowIfFalse(0 < EVP_KDF_derive(kctx, out.data(), out.size(), params));
    out.resize(length);

    return out;
}

} // namespace snet::tls