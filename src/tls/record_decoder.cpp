#include <casket/log/log_manager.hpp>
#include <casket/utils/exception.hpp>
#include <casket/utils/load_store.hpp>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/hash_traits.hpp>

#include <snet/tls/record_decoder.hpp>

using namespace casket;

namespace snet::tls
{

RecordDecoder::RecordDecoder()
    : cipher_(EVP_CIPHER_CTX_new())
    , seq_(0)
    , inited_(false)
{
    crypto::ThrowIfTrue(cipher_ == nullptr);
}

RecordDecoder::~RecordDecoder() noexcept
{
}

bool RecordDecoder::isInited() const noexcept
{
    return inited_;
}

void RecordDecoder::reset() noexcept
{
    EVP_CIPHER_CTX_reset(cipher_);
    seq_ = 0U;
    inited_ = false;
}

void RecordDecoder::init(const Cipher* cipher, nonstd::span<const uint8_t> encKey, nonstd::span<const uint8_t> encIV,
                         nonstd::span<const std::uint8_t> macKey)
{
    reset();

    macKey_.resize(macKey.size());
    memcpy(macKey_.data(), macKey.data(), macKey.size());

    crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, cipher, encKey.data(), encIV.data(), 0));
    inited_ = true;
}

void RecordDecoder::init(const Cipher* cipher, nonstd::span<const uint8_t> encKey, nonstd::span<const uint8_t> encIV)
{
    reset();

    implicitIv_.resize(encIV.size());
    memcpy(implicitIv_.data(), encIV.data(), encIV.size());

    crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, cipher, encKey.data(), nullptr, 0));
    inited_ = true;
}

void RecordDecoder::tls13UpdateKeys(const std::vector<uint8_t>& newkey, const std::vector<uint8_t>& newiv)
{
    crypto::ThrowIfFalse(0 < EVP_DecryptInit(cipher_, nullptr, newkey.data(), nullptr));
    std::copy(newiv.begin(), newiv.end(), implicitIv_.begin());
    seq_ = 0U;
}

size_t GetTagLength(EVP_CIPHER_CTX* ctx)
{
    if (EVP_CIPHER_CTX_get_mode(ctx) == EVP_CIPH_CCM_MODE)
    {
        return EVP_CCM_TLS_TAG_LEN;
    }
    return EVP_CIPHER_CTX_get_tag_length(ctx);
}

nonstd::span<std::uint8_t> RecordDecoder::tls13Decrypt(RecordType rt, nonstd::span<const uint8_t> in,
                                                       nonstd::span<uint8_t> out)
{
    int i;
    int x;
    std::array<uint8_t, TLS13_AEAD_AAD_SIZE> aad;
    std::array<uint8_t, 12> aead_nonce;

    memcpy(aead_nonce.data(), implicitIv_.data(), 12);

    // AEAD NONCE according to RFC TLS1.3
    for (i = 0; i < 8; i++)
    {
        aead_nonce[12 - 1 - i] ^= ((seq_ >> (i * 8)) & 0xFF);
    }
    seq_++;

    auto tagLength = GetTagLength(cipher_);
    auto data = in.subspan(0, in.size() - tagLength);
    auto tag = in.subspan(in.size() - tagLength, tagLength);

    aad[0] = static_cast<uint8_t>(rt);
    aad[1] = 0x03;
    aad[2] = 0x03;
    uint16_t size = static_cast<uint16_t>(in.size());
    aad[3] = casket::get_byte<0>(size);
    aad[4] = casket::get_byte<1>(size);

    crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr));

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_CCM_MODE)
    {
        crypto::ThrowIfFalse(
            0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_TAG, tag.size(), const_cast<uint8_t*>(tag.data())));
    }

    crypto::ThrowIfFalse(0 < EVP_DecryptInit_ex(cipher_, nullptr, nullptr, nullptr, aead_nonce.data()));

    int outSize{0};

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_CCM_MODE)
    {
        crypto::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, nullptr, &outSize, nullptr, data.size()));
    }

    crypto::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, nullptr, &outSize, aad.data(), aad.size()));

    outSize = data.size();

    casket::ThrowIfTrue(out.size() < data.size(), "too small buffer");
    crypto::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, out.data(), &outSize, data.data(), data.size()));

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_GCM_MODE)
    {
        crypto::ThrowIfFalse(
            0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_GCM_SET_TAG, tag.size(), const_cast<uint8_t*>(tag.data())));
        crypto::ThrowIfFalse(0 < EVP_DecryptFinal(cipher_, nullptr, &x));
    }

    return {out.data(), (size_t)outSize};
}

nonstd::span<uint8_t> RecordDecoder::tls1Decrypt(MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, RecordType rt,
                                                 ProtocolVersion version, nonstd::span<const uint8_t> in,
                                                 nonstd::span<uint8_t> out, bool encryptThenMac, bool aead)
{
    nonstd::span<std::uint8_t> decryptedContent;

    if (aead)
    {
        uint8_t aad[TLS12_AEAD_AAD_SIZE];

        auto recordIvSize = EVP_CIPHER_CTX_get_iv_length(cipher_);
        std::vector<uint8_t> aead_nonce;

        aead_nonce.reserve(recordIvSize);
        aead_nonce.insert(aead_nonce.end(), implicitIv_.begin(), implicitIv_.end());

        auto recordIv = in.subspan(0, recordIvSize - implicitIv_.size());
        in = in.subspan(recordIv.size());

        aead_nonce.insert(aead_nonce.end(), recordIv.begin(), recordIv.end());

        crypto::ThrowIfFalse(0 < EVP_DecryptInit(cipher_, nullptr, nullptr, aead_nonce.data()));

        auto tagLength = GetTagLength(cipher_);
        auto data = in.subspan(0, in.size() - tagLength);
        auto tag = in.subspan(in.size() - tagLength, tagLength);

        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(tag.size()),
                                                     const_cast<uint8_t*>(tag.data())));

        casket::store_be(seq_, &aad[0]);
        aad[8] = static_cast<uint8_t>(rt);
        aad[9] = version.majorVersion();
        aad[10] = version.minorVersion();
        uint16_t size = static_cast<uint16_t>(data.size());
        aad[11] = casket::get_byte<0>(size);
        aad[12] = casket::get_byte<1>(size);

        seq_++;

        int len{0};
        crypto::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, nullptr, &len, aad, sizeof(aad)));

        casket::ThrowIfTrue(out.size() < MAX_PLAINTEXT_SIZE, "output buffer is too small");
        crypto::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, out.data(), &len, data.data(), data.size()));

        int x{0};
        crypto::ThrowIfFalse(0 < EVP_DecryptFinal(cipher_, nullptr, &x));

        decryptedContent = {out.data(), (size_t)len};
    }
    /* Block cipher */
    else if (EVP_CIPHER_CTX_get_block_size(cipher_) > 1)
    {
        auto outSize = in.size();

        if (encryptThenMac)
        {
            auto mac = in.subspan(in.size() - crypto::GetHashSize(hmacHash));

            outSize -= mac.size();
            auto cipherText = in.subspan(0, outSize);

            crypto::ThrowIfFalse(0 < EVP_Cipher(cipher_, out.data(), cipherText.data(), cipherText.size()));

            uint8_t paddingLength = out[outSize - 1];
            paddingLength += 1;
            casket::ThrowIfTrue(paddingLength > outSize, "Invalid padding length");
            outSize -= paddingLength;

            if (version >= ProtocolVersion::TLSv1_1)
            {
                uint32_t blockSize = EVP_CIPHER_CTX_get_block_size(cipher_);
                casket::ThrowIfFalse(blockSize <= outSize, "Block size greater than Plaintext!");

                auto iv = in.subspan(0, blockSize);
                auto content = in.subspan(iv.size(), in.size() - iv.size() - mac.size());
                tls1CheckMac(hmacCtx, rt, version, iv, content, mac);

                outSize -= blockSize;
                decryptedContent = {out.data() + iv.size(), outSize};
            }
            else
            {
                auto content = in.subspan(0, in.size() - mac.size());
                tls1CheckMac(hmacCtx, rt, version, {}, content, mac);
                decryptedContent = {out.data(), outSize};
            }
        }
        else
        {
            auto cipherText = in.subspan(0, outSize);

            crypto::ThrowIfFalse(0 < EVP_Cipher(cipher_, out.data(), cipherText.data(), cipherText.size()));

            uint8_t paddingLength = out[outSize - 1];
            outSize -= (paddingLength + 1);

            auto mac = nonstd::span(out.begin() + outSize - crypto::GetHashSize(hmacHash), out.begin() + outSize);
            outSize -= mac.size();

            if (version >= ProtocolVersion::TLSv1_1)
            {
                uint32_t blockSize = EVP_CIPHER_CTX_get_block_size(cipher_);
                casket::ThrowIfFalse(blockSize <= outSize, "Block size greater than Plaintext!");

                auto content = nonstd::span(out.begin() + blockSize, out.begin() + outSize);
                tls1CheckMac(hmacCtx, rt, version, {}, content, mac);

                outSize -= blockSize;
            }
            else
            {
                auto content = nonstd::span(out.begin(), out.begin() + outSize);

                if (version == ProtocolVersion::SSLv3_0)
                {
                    ssl3CheckMac(hashCtx, hmacHash, rt, content, mac);
                }
                else
                {
                    tls1CheckMac(hmacCtx, rt, version, {}, content, mac);
                }
            }
            decryptedContent = {out.data(), outSize};
        }
    }
    /* Stream cipher */
    else if (EVP_CIPHER_CTX_get_block_size(cipher_) == 1)
    {
        crypto::ThrowIfFalse(0 < EVP_Cipher(cipher_, out.data(), in.data(), in.size()));

        auto content = nonstd::span(out.begin(), out.end() - crypto::GetHashSize(hmacHash));
        auto mac = nonstd::span(out.end() - crypto::GetHashSize(hmacHash), out.end());

        if (version == ProtocolVersion::SSLv3_0)
        {
            ssl3CheckMac(hashCtx, hmacHash, rt, content, mac);
        }
        else
        {
            tls1CheckMac(hmacCtx, rt, version, {}, content, mac);
        }

        decryptedContent = {out.data(), in.size() - mac.size()};
    }

    return decryptedContent;
}

void RecordDecoder::tls1CheckMac(MacCtx* hmacCtx, RecordType recordType, ProtocolVersion version,
                                 nonstd::span<const uint8_t> iv, nonstd::span<const uint8_t> content,
                                 nonstd::span<const uint8_t> expectedMac)
{
    std::array<uint8_t, 13> meta;
    casket::store_be(seq_, meta.data());
    seq_++;
    meta[8] = static_cast<uint8_t>(recordType);
    meta[9] = version.majorVersion();
    meta[10] = version.minorVersion();
    uint16_t s = content.size() + iv.size();
    meta[11] = casket::get_byte<0>(s);
    meta[12] = casket::get_byte<1>(s);

    crypto::ThrowIfFalse(0 < EVP_MAC_init(hmacCtx, macKey_.data(), macKey_.size(), nullptr));
    crypto::ThrowIfFalse(0 < EVP_MAC_update(hmacCtx, meta.data(), meta.size()));

    if (!iv.empty())
    {
        crypto::ThrowIfFalse(0 < EVP_MAC_update(hmacCtx, iv.data(), iv.size()));
    }

    crypto::ThrowIfFalse(0 < EVP_MAC_update(hmacCtx, content.data(), content.size()));

    std::array<uint8_t, EVP_MAX_MD_SIZE> actualMac;
    size_t actualMacSize = actualMac.size();
    crypto::ThrowIfFalse(0 < EVP_MAC_final(hmacCtx, actualMac.data(), &actualMacSize, actualMacSize));

    casket::ThrowIfFalse(expectedMac.size() == actualMacSize &&
                             std::equal(expectedMac.begin(), expectedMac.end(), actualMac.begin()),
                         "Bad record MAC");
}

void RecordDecoder::ssl3CheckMac(HashCtx* ctx, const Hash* hmacHash, RecordType recordType,
                                 nonstd::span<const uint8_t> content, nonstd::span<const uint8_t> expectedMac)
{
    int pad_ct = EVP_MD_is_a(hmacHash, "SHA1") > 0 ? 40 : 48;

    crypto::ThrowIfFalse(0 < EVP_DigestInit(ctx, hmacHash));
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, macKey_.data(), macKey_.size()));

    uint8_t buf[64];
    memset(buf, 0x36, pad_ct);
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, buf, pad_ct));

    std::array<uint8_t, 11> meta;
    casket::store_be(seq_, meta.data());
    seq_++;
    meta[8] = static_cast<uint8_t>(recordType);
    uint16_t s = content.size();
    meta[9] = casket::get_byte<0>(s);
    meta[10] = casket::get_byte<1>(s);

    std::array<uint8_t, EVP_MAX_MD_SIZE> actualMac;
    unsigned int actualMacSize = actualMac.size();

    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, meta.data(), meta.size()));
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, content.data(), content.size()));
    crypto::ThrowIfFalse(0 < EVP_DigestFinal(ctx, actualMac.data(), &actualMacSize));

    crypto::ThrowIfFalse(0 < EVP_DigestInit(ctx, hmacHash));
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, macKey_.data(), macKey_.size()));

    memset(buf, 0x5c, pad_ct);
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, buf, pad_ct));
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, actualMac.data(), actualMacSize));
    crypto::ThrowIfFalse(0 < EVP_DigestFinal(ctx, actualMac.data(), &actualMacSize));

    casket::ThrowIfFalse(expectedMac.size() == actualMacSize &&
                             std::equal(expectedMac.begin(), expectedMac.end(), actualMac.begin()),
                         "Bad record MAC");
}

} // namespace snet::tls