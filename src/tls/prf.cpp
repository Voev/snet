#include <algorithm>
#include <cstring>
#include <limits>

#include <snet/tls/prf.hpp>
#include <snet/tls/exception.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/cipher_suite.hpp>

#include <snet/utils/exception.hpp>
#include <snet/utils/load_store.hpp>

#include <openssl/kdf.h>
#include <openssl/core_names.h>

namespace snet::tls
{

void ssl3Prf(const Secret& secret, std::span<const uint8_t> clientRandom,
             std::span<const uint8_t> serverRandom, std::span<uint8_t> out)
{
    static const unsigned char* salt[3] = {
        (const unsigned char*)"A",
        (const unsigned char*)"BB",
        (const unsigned char*)"CCC",
    };

    unsigned char buf[EVP_MAX_MD_SIZE];
    unsigned int n;

    auto md5 = CipherSuiteManager::Instance().fetchDigest("MD5");
    auto sha1 = CipherSuiteManager::Instance().fetchDigest("SHA1");

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    tls::ThrowIfTrue(ctx == nullptr);

    for (size_t i = 0; i < 3; ++i)
    {
        tls::ThrowIfFalse(0 < EVP_DigestInit_ex(ctx, sha1, nullptr));
        tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, salt[i], strlen((const char*)salt[i])));
        tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, secret.data(), secret.size()));
        tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, clientRandom.data(), clientRandom.size()));
        tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, serverRandom.data(), serverRandom.size()));
        tls::ThrowIfFalse(0 < EVP_DigestFinal_ex(ctx, buf, &n));
        tls::ThrowIfFalse(0 < EVP_DigestInit_ex(ctx, md5, nullptr));
        tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, secret.data(), secret.size()));
        tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, buf, n));
        tls::ThrowIfFalse(0 < EVP_DigestFinal_ex(ctx, out.data(), &n));

        out = out.subspan(n);
    }
}

void tls1Prf(std::string_view algorithm, const Secret& secret, std::string_view label,
             std::span<const uint8_t> clientRandom, std::span<const uint8_t> serverRandom,
             std::span<uint8_t> out)
{
    auto kdf = CipherSuiteManager::Instance().fetchKdf("TLS1-PRF");
    tls::ThrowIfTrue(kdf == nullptr);

    EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf));
    tls::ThrowIfTrue(kctx == nullptr);

    OSSL_PARAM params[6], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            const_cast<char*>(algorithm.data()), algorithm.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET,
                                             const_cast<uint8_t*>(secret.data()), secret.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SEED, const_cast<char*>(label.data()),
                                             label.size());
    *p++ = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SEED, const_cast<uint8_t*>(clientRandom.data()), clientRandom.size());
    *p++ = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_SEED, const_cast<uint8_t*>(serverRandom.data()), serverRandom.size());
    *p = OSSL_PARAM_construct_end();

    tls::ThrowIfFalse(0 < EVP_KDF_derive(kctx, out.data(), out.size(), params));
}

std::vector<uint8_t> hkdfExpandLabel(std::string_view algorithm, const Secret& secret, std::string_view label,
                                     std::span<const uint8_t> context, const size_t length)
{
    // assemble (serialized) HkdfLabel
    std::vector<uint8_t> hkdfLabel;
    hkdfLabel.reserve(2 /* length */ + (label.size() + 6 /* 'tls13 ' */ + 1 /* length field*/) +
                      (context.size() + 1 /* length field*/));

    // length
    utils::ThrowIfFalse(length <= std::numeric_limits<uint16_t>::max(), "invalid length");
    const auto len = static_cast<uint16_t>(length);
    hkdfLabel.push_back(utils::get_byte<0>(len));
    hkdfLabel.push_back(utils::get_byte<1>(len));

    // label
    const std::string prefix = "tls13 ";
    utils::ThrowIfFalse(prefix.size() + label.size() <= 255, "label too large");
    hkdfLabel.push_back(static_cast<uint8_t>(prefix.size() + label.size()));
    hkdfLabel.insert(hkdfLabel.end(), prefix.cbegin(), prefix.cend());
    hkdfLabel.insert(hkdfLabel.end(), label.cbegin(), label.cend());

    // context
    utils::ThrowIfFalse(context.size() <= 255, "context too large");
    hkdfLabel.push_back(static_cast<uint8_t>(context.size()));
    hkdfLabel.insert(hkdfLabel.end(), context.begin(), context.end());

    auto kdf = CipherSuiteManager::Instance().fetchKdf("HKDF");

    EvpKdfCtxPtr kctx(EVP_KDF_CTX_new(kdf));
    tls::ThrowIfTrue(kctx == nullptr);

    static int mode{EVP_KDF_HKDF_MODE_EXPAND_ONLY};
    OSSL_PARAM params[6], *p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            const_cast<char*>(algorithm.data()), 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<uint8_t*>(secret.data()),
                                             secret.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<uint8_t*>(hkdfLabel.data()),
                                             hkdfLabel.size());
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p = OSSL_PARAM_construct_end();

    std::size_t outlen(length);
    std::vector<uint8_t> out(outlen);
    tls::ThrowIfFalse(0 < EVP_KDF_derive(kctx, out.data(), out.size(), params));
    out.resize(outlen);

    return out;
}

} // namespace snet::tls