#include <cassert>
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

    iv_.resize(encIV.size());
    memcpy(iv_.data(), encIV.data(), encIV.size());

    key_.resize(encKey.size());
    memcpy(key_.data(), encKey.data(), encKey.size());

    crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, cipher, nullptr, nullptr, 0));
    inited_ = true;
}

void RecordDecoder::tls13UpdateKeys(const std::vector<uint8_t>& newkey, const std::vector<uint8_t>& newiv)
{
    std::copy(newkey.begin(), newkey.end(), key_.begin());
    std::copy(newiv.begin(), newiv.end(), iv_.begin());
    seq_ = 0U;
}

nonstd::span<std::uint8_t> RecordDecoder::tls13Decrypt(RecordType rt, nonstd::span<const uint8_t> in,
                                                       nonstd::span<uint8_t> out, int tagLength)
{
    int i;
    int updateLength = 0;
    int finalLength = 0;
    std::array<uint8_t, TLS13_AEAD_AAD_SIZE> aad;
    std::array<uint8_t, TLS13_AEAD_NONCE_SIZE> nonce;

    memcpy(nonce.data(), iv_.data(), 12);

    assert(tagLength > 0);

    // AEAD NONCE according to RFC TLS1.3
    for (i = 0; i < 8; i++)
    {
        nonce[12 - 1 - i] ^= ((seq_ >> (i * 8)) & 0xFF);
    }
    seq_++;

    int dataLength = in.size() - tagLength;

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_CCM_MODE)
    {
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_IVLEN, EVP_CCM_TLS_IV_LEN, nullptr));
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_TAG, tagLength, nullptr));
        crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, nullptr, key_.data(), nonce.data(), 0));
    }
    else
    {
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr));
        crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, nullptr, key_.data(), nonce.data(), 0));
    }

    crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_TAG, tagLength,
                                                 const_cast<uint8_t*>(in.data()) + dataLength));

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_CCM_MODE)
    {
        crypto::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, nullptr, &updateLength, nullptr, dataLength));
    }

    aad[0] = static_cast<uint8_t>(rt);
    aad[1] = 0x03;
    aad[2] = 0x03;
    uint16_t size = static_cast<uint16_t>(in.size());
    aad[3] = casket::get_byte<0>(size);
    aad[4] = casket::get_byte<1>(size);

    crypto::ThrowIfFalse(0 < EVP_CipherUpdate(cipher_, nullptr, &updateLength, aad.data(), aad.size()));
    crypto::ThrowIfFalse(0 < EVP_CipherUpdate(cipher_, out.data(), &updateLength, in.data(), dataLength));
    crypto::ThrowIfFalse(0 < EVP_CipherFinal(cipher_, out.data() + updateLength, &finalLength));

    return {out.data(), (size_t)updateLength};
}

nonstd::span<uint8_t> RecordDecoder::tls1Decrypt(MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, RecordType rt,
                                                 ProtocolVersion version, nonstd::span<const uint8_t> in,
                                                 nonstd::span<uint8_t> out, int tagLength, bool encryptThenMac,
                                                 bool aead)
{
    nonstd::span<std::uint8_t> decryptedContent;

    if (aead)
    {
        std::array<uint8_t, TLS12_AEAD_AAD_SIZE> aad;
        const auto mode = EVP_CIPHER_CTX_mode(cipher_);

        if (mode == EVP_CIPH_GCM_MODE)
        {
            crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_GCM_SET_IV_FIXED, iv_.size(), iv_.data()));
            crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, nullptr, key_.data(), nullptr, 0));
        }
        else if (mode == EVP_CIPH_CCM_MODE)
        {
            crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_CCM_SET_IV_FIXED, iv_.size(), iv_.data()));
            crypto::ThrowIfFalse(0 <
                                 EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_IVLEN, EVP_CCM_TLS_IV_LEN, nullptr));
            crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_TAG, tagLength, nullptr));
            crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, nullptr, key_.data(), nullptr, 0));
        }
        else
        {
            auto recordIvSize = EVP_CIPHER_CTX_iv_length(cipher_);
            std::vector<uint8_t> nonce;

            nonce.reserve(recordIvSize);
            nonce.insert(nonce.end(), iv_.begin(), iv_.end());

            auto recordIv = in.subspan(0, recordIvSize - iv_.size());

            nonce.insert(nonce.end(), recordIv.begin(), recordIv.end());

            crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, nullptr, key_.data(), nonce.data(), 0));
        }

        casket::store_be(seq_, &aad[0]);
        aad[8] = static_cast<uint8_t>(rt);
        aad[9] = version.majorVersion();
        aad[10] = version.minorVersion();
        uint16_t size = static_cast<uint16_t>(in.size());
        aad[11] = casket::get_byte<0>(size);
        aad[12] = casket::get_byte<1>(size);

        auto tagLength = EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_TLS1_AAD, static_cast<int>(aad.size()),
                                             const_cast<uint8_t*>(aad.data()));
        crypto::ThrowIfFalse(tagLength > 0, "Invalid tag length");

        seq_++;

        casket::ThrowIfTrue(out.size() < MAX_PLAINTEXT_SIZE, "output buffer is too small");

        out = {const_cast<uint8_t*>(in.data()), in.size()};
        auto len = EVP_Cipher(cipher_, out.data(), in.data(), in.size());
        crypto::ThrowIfFalse(len > 0, "Bad record MAC");

        if (mode == EVP_CIPH_GCM_MODE)
        {
            out = out.subspan(EVP_GCM_TLS_EXPLICIT_IV_LEN);
            len -= EVP_GCM_TLS_EXPLICIT_IV_LEN + tagLength;
        }
        else if (EVP_CIPHER_CTX_mode(cipher_) == EVP_CIPH_CCM_MODE)
        {
            out = out.subspan(EVP_CCM_TLS_EXPLICIT_IV_LEN);
            len -= EVP_CCM_TLS_EXPLICIT_IV_LEN + tagLength;
        }

        decryptedContent = {out.data(), static_cast<size_t>(len)};
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