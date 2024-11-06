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

void ssl3_prf(const Secret& secret, std::string_view usage,
              std::span<const uint8_t> r1, std::span<const uint8_t> r2,
              std::span<uint8_t> out)
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

void tls_P_hash(const Secret& secret, std::span<const uint8_t> seed,
                const EVP_MD* md, std::span<uint8_t> out)
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

void tls_prf(const Secret& secret, std::string_view usage,
             std::span<const uint8_t> rnd1, std::span<const uint8_t> rnd2,
             std::span<uint8_t> out)
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
               std::span<const uint8_t> rnd1, std::span<const uint8_t> rnd2,
               std::span<uint8_t> out)
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

std::vector<uint8_t> hkdfExpandLabel(const EVP_MD* md, const Secret& secret,
                                     std::string_view label,
                                     std::span<const uint8_t> context,
                                     const size_t length)
{

    // assemble (serialized) HkdfLabel
    std::vector<uint8_t> hkdf_label;
    hkdf_label.reserve(2 /* length */ +
                       (label.size() + 6 /* 'tls13 ' */ + 1 /* length field*/) +
                       (context.size() + 1 /* length field*/));

    // length
    utils::ThrowIfFalse(length <= std::numeric_limits<uint16_t>::max(),
                        "invalid length");
    const auto len = static_cast<uint16_t>(length);
    hkdf_label.push_back(getByte<0>(len));
    hkdf_label.push_back(getByte<1>(len));

    // label
    const std::string prefix = "tls13 ";
    utils::ThrowIfFalse(prefix.size() + label.size() <= 255, "label too large");
    hkdf_label.push_back(static_cast<uint8_t>(prefix.size() + label.size()));
    hkdf_label.insert(hkdf_label.end(), prefix.cbegin(), prefix.cend());
    hkdf_label.insert(hkdf_label.end(), label.cbegin(), label.cend());

    // context
    utils::ThrowIfFalse(context.size() <= 255, "context too large");
    hkdf_label.push_back(static_cast<uint8_t>(context.size()));
    hkdf_label.insert(hkdf_label.end(), context.begin(), context.end());

    EvpPkeyCtxPtr pctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    ThrowIfFalse(pctx != nullptr);

    ThrowIfFalse(0 < EVP_PKEY_derive_init(pctx));
    ThrowIfFalse(0 <
                 EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY));
    ThrowIfFalse(0 < EVP_PKEY_CTX_set_hkdf_md(pctx, md));
    ThrowIfFalse(
        0 < EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.data(), secret.size()));

    ThrowIfFalse(0 < EVP_PKEY_CTX_add1_hkdf_info(pctx, hkdf_label.data(),
                                                 hkdf_label.size()));

    std::size_t outlen(length);
    std::vector<uint8_t> out(outlen);
    ThrowIfFalse(0 < EVP_PKEY_derive(pctx, out.data(), &outlen));
    out.resize(outlen);

    return out;
}

} // namespace snet::tls