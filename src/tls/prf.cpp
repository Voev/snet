#include <algorithm>
#include <cstring>
#include <limits>

#include <snet/tls/prf.hpp>
#include <snet/tls/exception.hpp>
#include <snet/tls/types.hpp>

#include <snet/utils/exception.hpp>

#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>

namespace snet::tls
{

void ssl3_prf(const Secret& secret, std::string_view usage, std::span<const uint8_t> r1,
              std::span<const uint8_t> r2, std::span<uint8_t> out)
{
    MD5_CTX md5;
    SHA_CTX sha;
    int i = 0, j;
    uint8_t buf[20];

    MD5_Init(&md5);
    memset(&sha, 0, sizeof(sha));
    SHA1_Init(&sha);

    for (size_t off = 0; off < out.size(); off += 16)
    {
        char outbuf[16];
        int tocpy;
        i++;

        /* A, BB, CCC,  ... */
        for (j = 0; j < i; j++)
        {
            buf[j] = 64 + i;
        }

        SHA1_Update(&sha, buf, i);

        if (!secret.empty())
            SHA1_Update(&sha, secret.data(), secret.size());

        if (usage == "client write key" || usage == "server write key")
        {
            SHA1_Update(&sha, r2.data(), r2.size());
            SHA1_Update(&sha, r1.data(), r1.size());
        }
        else
        {
            SHA1_Update(&sha, r1.data(), r1.size());
            SHA1_Update(&sha, r2.data(), r2.size());
        }

        SHA1_Final(buf, &sha);

        SHA1_Init(&sha);

        if (!secret.empty())
            MD5_Update(&md5, secret.data(), secret.size());

        MD5_Update(&md5, buf, 20);
        MD5_Final((unsigned char*)outbuf, &md5);

        tocpy = std::min(out.size() - off, 16UL);
        memcpy(out.data() + off, outbuf, tocpy);

        MD5_Init(&md5);
    }
}

int tls1_prf_P_hash(EVP_MAC_CTX* ctx_init, const Secret& secret, std::span<const uint8_t> seed,
                    std::span<uint8_t> out)
{
    size_t chunk;
    EVP_MAC_CTX *ctx = NULL, *ctx_Ai = NULL;
    unsigned char Ai[EVP_MAX_MD_SIZE];
    size_t Ai_len;
    int ret = 0;

    if (!EVP_MAC_init(ctx_init, secret.data(), secret.size(), NULL))
        goto err;
    chunk = EVP_MAC_CTX_get_mac_size(ctx_init);
    if (chunk == 0)
        goto err;
    /* A(0) = seed */
    ctx_Ai = EVP_MAC_CTX_dup(ctx_init);
    if (ctx_Ai == NULL)
        goto err;
    if (!seed.empty() && !EVP_MAC_update(ctx_Ai, seed.data(), seed.size()))
        goto err;

    for (;;)
    {
        /* calc: A(i) = HMAC_<hash>(secret, A(i-1)) */
        if (!EVP_MAC_final(ctx_Ai, Ai, &Ai_len, sizeof(Ai)))
            goto err;
        EVP_MAC_CTX_free(ctx_Ai);
        ctx_Ai = NULL;

        /* calc next chunk: HMAC_<hash>(secret, A(i) + seed) */
        ctx = EVP_MAC_CTX_dup(ctx_init);
        if (ctx == NULL)
            goto err;
        if (!EVP_MAC_update(ctx, Ai, Ai_len))
            goto err;
        /* save state for calculating next A(i) value */
        if (out.size() > chunk)
        {
            ctx_Ai = EVP_MAC_CTX_dup(ctx);
            if (ctx_Ai == NULL)
                goto err;
        }
        if (!seed.empty() && !EVP_MAC_update(ctx, seed.data(), seed.size()))
            goto err;
        if (out.size() <= chunk)
        {
            /* last chunk - use Ai as temp bounce buffer */
            if (!EVP_MAC_final(ctx, Ai, &Ai_len, sizeof(Ai)))
                goto err;
            memcpy(out.data(), Ai, out.size());
            break;
        }
        if (!EVP_MAC_final(ctx, out.data(), NULL, out.size()))
            goto err;
        EVP_MAC_CTX_free(ctx);
        ctx = NULL;
        out = out.subspan(chunk);
    }
    ret = 1;
err:
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_CTX_free(ctx_Ai);
    OPENSSL_cleanse(Ai, sizeof(Ai));
    return ret;
}

void tls_P_hash(const Secret& secret, std::span<const uint8_t> seed, const EVP_MD* md,
                std::span<uint8_t> out)
{
    uint8_t* ptr = out.data();
    unsigned int left = out.size();
    int tocpy;
    const uint8_t* A;
    uint8_t _A[128], tmp[128];
    unsigned int A_l, tmp_l;
    HMAC_CTX* hm = HMAC_CTX_new();

    A = seed.data();
    A_l = seed.size();

    while (left)
    {
        HMAC_Init_ex(hm, secret.data(), secret.size(), md, NULL);
        HMAC_Update(hm, A, A_l);
        HMAC_Final(hm, _A, &A_l);
        A = _A;

        HMAC_Init_ex(hm, secret.data(), secret.size(), md, NULL);
        HMAC_Update(hm, A, A_l);
        HMAC_Update(hm, seed.data(), seed.size());
        HMAC_Final(hm, tmp, &tmp_l);

        tocpy = std::min(left, tmp_l);
        memcpy(ptr, tmp, tocpy);
        ptr += tocpy;
        left -= tocpy;
    }

    HMAC_CTX_free(hm);
}

void tls_prf(const Secret& secret, std::string_view usage, std::span<const uint8_t> rnd1,
             std::span<const uint8_t> rnd2, std::span<uint8_t> out)
{

    std::vector<uint8_t> md5_out;
    std::vector<uint8_t> sha_out;
    std::vector<uint8_t> seed;
    std::vector<uint8_t> S1;
    std::vector<uint8_t> S2;

    md5_out.resize(std::max(out.size(), 16UL));
    sha_out.resize(std::max(out.size(), 20UL));

    seed.reserve(usage.size() + rnd1.size() + rnd2.size());
    seed.insert(seed.end(), usage.cbegin(), usage.cend());
    seed.insert(seed.end(), rnd1.begin(), rnd1.end());
    seed.insert(seed.end(), rnd2.begin(), rnd2.end());

    auto S_l = secret.size() / 2 + secret.size() % 2;

    S1.resize(S_l);
    S2.resize(S_l);

    memcpy(S1.data(), secret.data(), S_l);
    memcpy(S2.data(), secret.data() + (secret.size() - S_l), S_l);

    tls_P_hash(S1, seed, EVP_get_digestbyname("MD5"), md5_out);
    tls_P_hash(S2, seed, EVP_get_digestbyname("SHA1"), sha_out);

    for (size_t i = 0; i < out.size(); i++)
        out[i] = md5_out[i] ^ sha_out[i];
}

void tls12_prf(const EVP_MD* md, const Secret& secret, std::string_view usage,
               std::span<const uint8_t> rnd1, std::span<const uint8_t> rnd2, std::span<uint8_t> out)
{

    std::vector<uint8_t> sha_out;
    std::vector<uint8_t> seed;

    sha_out.resize(std::max(out.size(), static_cast<size_t>(EVP_MAX_MD_SIZE)));
    seed.reserve(usage.size() + rnd1.size() + rnd2.size());
    seed.insert(seed.end(), usage.cbegin(), usage.cend());
    seed.insert(seed.end(), rnd1.begin(), rnd1.end());
    seed.insert(seed.end(), rnd2.begin(), rnd2.end());

    tls_P_hash(secret, seed, md, sha_out);

    for (size_t i = 0; i < out.size(); i++)
        out[i] = sha_out[i];
}

template <size_t B, typename T>
inline constexpr uint8_t getByte(T input) requires(B < sizeof(T))
{
    const size_t shift = ((~B) & (sizeof(T) - 1)) << 3;
    return static_cast<uint8_t>((input >> shift) & 0xFF);
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
    hkdfLabel.push_back(getByte<0>(len));
    hkdfLabel.push_back(getByte<1>(len));

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