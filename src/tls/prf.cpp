#include <algorithm>
#include <cstring>
#include <limits>

#include <snet/tls/prf.hpp>
#include <snet/tls/exception.hpp>
#include <snet/tls/types.hpp>

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

    EvpMdPtr md5(EVP_MD_fetch(nullptr, "MD5", nullptr));
    tls::ThrowIfTrue(md5 == nullptr);

    EvpMdPtr sha1(EVP_MD_fetch(nullptr, "SHA1", nullptr));
    tls::ThrowIfTrue(sha1 == nullptr);

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
    EvpKdfPtr kdf(EVP_KDF_fetch(nullptr, "TLS1-PRF", nullptr));
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

std::vector<uint8_t> hkdfExpandLabel(const EVP_MD* md, const Secret& secret, std::string_view label,
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

    EvpPkeyCtxPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    tls::ThrowIfFalse(pctx != nullptr);

    tls::ThrowIfFalse(0 < EVP_PKEY_derive_init(pctx));
    tls::ThrowIfFalse(0 < EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY));
    tls::ThrowIfFalse(0 < EVP_PKEY_CTX_set_hkdf_md(pctx, md));
    tls::ThrowIfFalse(0 < EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.data(), secret.size()));

    tls::ThrowIfFalse(0 < EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdfLabel.data(), hkdfLabel.size()));

    std::size_t outlen(length);
    std::vector<uint8_t> out(outlen);
    tls::ThrowIfFalse(0 < EVP_PKEY_derive(pctx, out.data(), &outlen));
    out.resize(outlen);

    return out;
}

} // namespace snet::tls