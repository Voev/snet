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
{
    crypto::ThrowIfTrue(cipher_ == nullptr);
}

RecordDecoder::~RecordDecoder() noexcept
{
}

void RecordDecoder::reset() noexcept
{
    EVP_CIPHER_CTX_reset(cipher_);
}

void RecordDecoder::init(const Cipher* cipher)
{
    reset();

    crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, cipher, nullptr, nullptr, 0));
}

void RecordDecoder::init(const Cipher* cipher, nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv)
{
    reset();

    crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, cipher, key.data(), iv.data(), 0));
}

nonstd::span<std::uint8_t> RecordDecoder::tls13Encrypt(RecordType rt, uint64_t seq, nonstd::span<const uint8_t> key,
                                                       nonstd::span<const uint8_t> iv, nonstd::span<const uint8_t> in,
                                                       nonstd::span<uint8_t> out, int tagLength)
{
    return tls13process(rt, seq, key, iv, in, out, tagLength, true);
}

nonstd::span<std::uint8_t> RecordDecoder::tls13Decrypt(RecordType rt, uint64_t seq, nonstd::span<const uint8_t> key,
                                                       nonstd::span<const uint8_t> iv, nonstd::span<const uint8_t> in,
                                                       nonstd::span<uint8_t> out, int tagLength)
{
    return tls13process(rt, seq, key, iv, in, out, tagLength, false);
}

nonstd::span<std::uint8_t> RecordDecoder::tls13process(RecordType rt, uint64_t seq, nonstd::span<const uint8_t> key,
                                                       nonstd::span<const uint8_t> iv, nonstd::span<const uint8_t> in,
                                                       nonstd::span<uint8_t> out, int tagLength, bool encrypt)
{
    int updateLength = 0;
    int finalLength = 0;
    std::array<uint8_t, TLS13_AEAD_AAD_SIZE> aad;
    std::array<uint8_t, TLS13_AEAD_NONCE_SIZE> nonce;

    casket::ThrowIfFalse(iv.size() >= TLS13_AEAD_NONCE_SIZE, "Invalid IV size");
    std::copy_n(iv.begin(), TLS13_AEAD_NONCE_SIZE, nonce.begin());

    assert(tagLength > 0);

    for (int i = 0; i < 8; ++i)
    {
        nonce[TLS13_AEAD_NONCE_SIZE - 1 - i] ^= ((seq >> (i * 8)) & 0xFF);
    }

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_CCM_MODE)
    {
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_IVLEN, EVP_CCM_TLS_IV_LEN, nullptr));
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_TAG, tagLength, nullptr));
        crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, nullptr, key.data(), nonce.data(), static_cast<int>(encrypt)));
    }
    else
    {
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr));
        crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, nullptr, key.data(), nonce.data(), static_cast<int>(encrypt)));
    }

    int dataLength = in.size();
    uint16_t encryptedRecordLength = static_cast<uint16_t>(in.size());

    if (!encrypt)
    {
        /// TLSv1.3 uses 1 byte to denote inner content type.
        casket::ThrowIfFalse(in.size() >= static_cast<size_t>(tagLength) + 1, "Invalid data size");
        dataLength -= tagLength;

        /// Set tag for decryption.
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_TAG, tagLength,
                                                     const_cast<uint8_t*>(in.data()) + dataLength));
    }
    else
    {
        /// Calculate size for AAD
        encryptedRecordLength += tagLength;
    }

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_CCM_MODE)
    {
        crypto::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, nullptr, &updateLength, nullptr, dataLength));
    }

    aad[0] = static_cast<uint8_t>(rt);
    aad[1] = 0x03;
    aad[2] = 0x03;
    aad[3] = casket::get_byte<0>(encryptedRecordLength);
    aad[4] = casket::get_byte<1>(encryptedRecordLength);

    crypto::ThrowIfFalse(0 < EVP_CipherUpdate(cipher_, nullptr, &updateLength, aad.data(), aad.size()));
    crypto::ThrowIfFalse(0 < EVP_CipherUpdate(cipher_, out.data(), &updateLength, in.data(), dataLength));
    crypto::ThrowIfFalse(0 < EVP_CipherFinal(cipher_, out.data() + updateLength, &finalLength), "Bad record MAC");

    casket::ThrowIfFalse(dataLength == updateLength + finalLength, "Invalid processed length");

    if (encrypt)
    {
        /// Add the tag
        crypto::ThrowIfFalse(0 <
                             EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_GET_TAG, tagLength, out.data() + dataLength));
        dataLength += tagLength;
    }

    return {out.data(), static_cast<size_t>(dataLength)};
}

nonstd::span<uint8_t> RecordDecoder::tls1Decrypt(MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, RecordType rt,
                                                 ProtocolVersion version, uint64_t seq, nonstd::span<const uint8_t> key,
                                                 nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv,
                                                 nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out,
                                                 int tagLength, bool encryptThenMac, bool aead)
{
    nonstd::span<std::uint8_t> decryptedContent;

    if (aead)
    {
        std::array<uint8_t, TLS12_AEAD_AAD_SIZE> aad;
        const auto mode = EVP_CIPHER_CTX_mode(cipher_);

        if (mode == EVP_CIPH_GCM_MODE)
        {
            crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_GCM_SET_IV_FIXED, iv.size(),
                                                         const_cast<uint8_t*>(iv.data())));
            crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, nullptr, key.data(), nullptr, 0));
        }
        else if (mode == EVP_CIPH_CCM_MODE)
        {
            crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_CCM_SET_IV_FIXED, iv.size(),
                                                         const_cast<uint8_t*>(iv.data())));
            crypto::ThrowIfFalse(0 <
                                 EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_IVLEN, EVP_CCM_TLS_IV_LEN, nullptr));
            crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_TAG, tagLength, nullptr));
            crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, nullptr, key.data(), nullptr, 0));
        }
        else
        {
            std::array<uint8_t, 2 * EVP_MAX_IV_LENGTH> nonce;
            const size_t recordIvSize = EVP_CIPHER_CTX_iv_length(cipher_);

            casket::ThrowIfFalse(recordIvSize <= nonce.size(), "IV too large");
            casket::ThrowIfFalse(recordIvSize >= iv.size(), "IV too small");
            casket::ThrowIfFalse(in.size() >= recordIvSize - iv.size(), "Not enough input");

            std::copy_n(iv.begin(), iv.size(), nonce.begin());
            std::copy_n(in.begin(), recordIvSize - iv.size(), nonce.begin() + iv.size());

            crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, nullptr, key.data(), nonce.data(), 0));
        }

        casket::store_be(seq, &aad[0]);
        aad[8] = static_cast<uint8_t>(rt);
        aad[9] = version.majorVersion();
        aad[10] = version.minorVersion();
        uint16_t size = static_cast<uint16_t>(in.size());
        aad[11] = casket::get_byte<0>(size);
        aad[12] = casket::get_byte<1>(size);

        auto tagLength = EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_TLS1_AAD, static_cast<int>(aad.size()),
                                             const_cast<uint8_t*>(aad.data()));
        crypto::ThrowIfFalse(tagLength > 0, "Invalid tag length");

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
                tls1CheckMac(hmacCtx, rt, version, seq, macKey, iv, content, mac);

                outSize -= blockSize;
                decryptedContent = {out.data() + iv.size(), outSize};
            }
            else
            {
                auto content = in.subspan(0, in.size() - mac.size());
                tls1CheckMac(hmacCtx, rt, version, seq, macKey, {}, content, mac);
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
                tls1CheckMac(hmacCtx, rt, version, seq, macKey, {}, content, mac);

                outSize -= blockSize;
            }
            else
            {
                auto content = nonstd::span(out.begin(), out.begin() + outSize);

                if (version == ProtocolVersion::SSLv3_0)
                {
                    ssl3CheckMac(hashCtx, hmacHash, rt, seq, macKey, content, mac);
                }
                else
                {
                    tls1CheckMac(hmacCtx, rt, version, seq, macKey, {}, content, mac);
                }
            }
            decryptedContent = {out.data(), outSize};
        }
    }
    /* Stream cipher */
    else if (EVP_CIPHER_CTX_get_block_size(cipher_) == 1)
    {
        crypto::ThrowIfFalse(0 < EVP_CipherInit(cipher_, nullptr, key.data(), iv.data(), 0));
        crypto::ThrowIfFalse(0 < EVP_Cipher(cipher_, out.data(), in.data(), in.size()));

        auto content = nonstd::span(out.begin(), out.end() - crypto::GetHashSize(hmacHash));
        auto mac = nonstd::span(out.end() - crypto::GetHashSize(hmacHash), out.end());

        if (version == ProtocolVersion::SSLv3_0)
        {
            ssl3CheckMac(hashCtx, hmacHash, rt, seq, macKey, content, mac);
        }
        else
        {
            tls1CheckMac(hmacCtx, rt, version, seq, macKey, {}, content, mac);
        }

        decryptedContent = {out.data(), in.size() - mac.size()};
    }

    return decryptedContent;
}

void RecordDecoder::tls1CheckMac(MacCtx* hmacCtx, RecordType recordType, ProtocolVersion version, uint64_t seq,
                                 nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv,
                                 nonstd::span<const uint8_t> content, nonstd::span<const uint8_t> expectedMac)
{
    std::array<uint8_t, 13> meta;
    casket::store_be(seq, meta.data());

    meta[8] = static_cast<uint8_t>(recordType);
    meta[9] = version.majorVersion();
    meta[10] = version.minorVersion();
    uint16_t s = content.size() + iv.size();
    meta[11] = casket::get_byte<0>(s);
    meta[12] = casket::get_byte<1>(s);

    crypto::ThrowIfFalse(0 < EVP_MAC_init(hmacCtx, macKey.data(), macKey.size(), nullptr));
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

void RecordDecoder::ssl3CheckMac(HashCtx* ctx, const Hash* hmacHash, RecordType recordType, uint64_t seq,
                                 nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> content,
                                 nonstd::span<const uint8_t> expectedMac)
{
    int pad_ct = EVP_MD_is_a(hmacHash, "SHA1") > 0 ? 40 : 48;

    crypto::ThrowIfFalse(0 < EVP_DigestInit(ctx, hmacHash));
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, macKey.data(), macKey.size()));

    uint8_t buf[64];
    memset(buf, 0x36, pad_ct);
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, buf, pad_ct));

    std::array<uint8_t, 11> meta;
    casket::store_be(seq, meta.data());

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
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, macKey.data(), macKey.size()));

    memset(buf, 0x5c, pad_ct);
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, buf, pad_ct));
    crypto::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, actualMac.data(), actualMacSize));
    crypto::ThrowIfFalse(0 < EVP_DigestFinal(ctx, actualMac.data(), &actualMacSize));

    casket::ThrowIfFalse(expectedMac.size() == actualMacSize &&
                             std::equal(expectedMac.begin(), expectedMac.end(), actualMac.begin()),
                         "Bad record MAC");
}

} // namespace snet::tls