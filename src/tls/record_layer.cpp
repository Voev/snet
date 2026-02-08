#include <cassert>
#include <cstring>

#include <casket/log/log_manager.hpp>
#include <casket/utils/exception.hpp>
#include <casket/utils/load_store.hpp>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/cipher_traits.hpp>
#include <snet/crypto/hash_traits.hpp>
#include <snet/crypto/hmac_traits.hpp>

#include <snet/tls/record_layer.hpp>

using namespace casket;
using namespace snet::crypto;

namespace snet::tls
{

void RecordLayer::init(CipherCtx* ctx, const Cipher* cipher)
{
    crypto::ThrowIfFalse(0 < EVP_CipherInit(ctx, cipher, nullptr, nullptr, 0));
}

void RecordLayer::init(CipherCtx* ctx, const Cipher* cipher, nonstd::span<const uint8_t> key,
                       nonstd::span<const uint8_t> iv)
{
    crypto::ThrowIfFalse(0 < EVP_CipherInit(ctx, cipher, key.data(), iv.data(), 0));
}

void RecordLayer::encrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, Record* record,
                          uint64_t seq, nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> macKey,
                          nonstd::span<const uint8_t> iv)
{
    if (version_ == ProtocolVersion::TLSv1_3)
    {
        doTLSv13Encrypt(cipherCtx, record, seq, key, iv);
    }
    else if (aead_)
    {
        doTLSv1AeadEncrypt(cipherCtx, record, seq, key, iv);
    }
    else
    {
        doTLSv1Encrypt(cipherCtx, hmacCtx, hashCtx, hmacHash, record, seq, key, macKey, iv);
    }

    record->isDecrypted_ = false;
}

void RecordLayer::decrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, Record* record,
                          uint64_t seq, nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> macKey,
                          nonstd::span<const uint8_t> iv)
{
    if (version_ == ProtocolVersion::TLSv1_3)
    {
        doTLSv13Decrypt(cipherCtx, record, seq, key, iv);
    }
    else if (aead_)
    {
        doTLSv1AeadDecrypt(cipherCtx, record, seq, key, iv);
    }
    else
    {
        doTLSv1Decrypt(cipherCtx, hmacCtx, hashCtx, hmacHash, record, seq, key, macKey, iv);
    }

    record->isDecrypted_ = true;
}

void RecordLayer::doTLSv1Encrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash,
                                 Record* record, uint64_t seq, nonstd::span<const uint8_t> key,
                                 nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv)
{
    /// @todo Implementation
    (void)cipherCtx;
    (void)hmacCtx;
    (void)hashCtx;
    (void)hmacHash;
    (void)record;
    (void)seq;
    (void)key;
    (void)macKey;
    (void)iv;
}

void RecordLayer::doTLSv1Decrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash,
                                 Record* record, uint64_t seq, nonstd::span<const uint8_t> key,
                                 nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv)
{
    auto input = record->getCiphertext();

    record->plaintext_ = doTLSv1Process(cipherCtx, hmacCtx, hashCtx, hmacHash, record->getType(), seq, key, macKey, iv,
                                        input.subspan(TLS_HEADER_SIZE), record->plaintextBuffer_, false);

    record->isDecrypted_ = true;
}

void RecordLayer::doTLSv1AeadEncrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq,
                                     nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv)
{
    auto input = record->getPlaintext();
    auto result = doTLSv1AeadProcess(cipherCtx, record->getType(), seq, key, iv, input.subspan(TLS_HEADER_SIZE), true);

    record->ciphertext_ = {input.data(), TLS_HEADER_SIZE + result.size()};
    record->isDecrypted_ = false;
}

void RecordLayer::doTLSv1AeadDecrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq,
                                     nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv)
{
    auto input = record->getCiphertext();
    
    record->plaintext_ = doTLSv1AeadProcess(cipherCtx, record->getType(), seq, key, iv, input.subspan(TLS_HEADER_SIZE), false);
    record->isDecrypted_ = true;
}

nonstd::span<uint8_t> RecordLayer::doTLSv1AeadProcess(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                                      nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv,
                                                      nonstd::span<uint8_t> in, bool encrypt)
{
    std::array<uint8_t, TLS12_AEAD_AAD_SIZE> aad;
    const auto mode = CipherTraits::getMode(cipherCtx);

    if (mode == EVP_CIPH_GCM_MODE)
    {
        crypto::ThrowIfFalse(
            0 < EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_GCM_SET_IV_FIXED, iv.size(), const_cast<uint8_t*>(iv.data())));
        crypto::ThrowIfFalse(0 < EVP_CipherInit(cipherCtx, nullptr, key.data(), nullptr, static_cast<int>(encrypt)));
    }
    else if (mode == EVP_CIPH_CCM_MODE)
    {
        crypto::ThrowIfFalse(
            0 < EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_CCM_SET_IV_FIXED, iv.size(), const_cast<uint8_t*>(iv.data())));
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_AEAD_SET_IVLEN, EVP_CCM_TLS_IV_LEN, nullptr));
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_AEAD_SET_TAG, tagLength_, nullptr));
        crypto::ThrowIfFalse(0 < EVP_CipherInit(cipherCtx, nullptr, key.data(), nullptr, static_cast<int>(encrypt)));
    }
    else
    {
        std::array<uint8_t, 2 * EVP_MAX_IV_LENGTH> nonce;
        const size_t recordIvSize = EVP_CIPHER_CTX_iv_length(cipherCtx);

        casket::ThrowIfFalse(recordIvSize <= nonce.size(), "IV too large");
        casket::ThrowIfFalse(recordIvSize >= iv.size(), "IV too small");
        casket::ThrowIfFalse(in.size() >= recordIvSize - iv.size(), "Not enough input");

        std::copy_n(iv.begin(), iv.size(), nonce.begin());
        std::copy_n(in.begin(), recordIvSize - iv.size(), nonce.begin() + iv.size());

        crypto::ThrowIfFalse(0 <
                             EVP_CipherInit(cipherCtx, nullptr, key.data(), nonce.data(), static_cast<int>(encrypt)));
    }

    uint16_t inputLength = in.size();
    casket::store_be(seq, &aad[0]);

    aad[8] = static_cast<uint8_t>(rt);
    aad[9] = version_.majorVersion();
    aad[10] = version_.minorVersion();
    aad[11] = casket::get_byte<0>(inputLength);
    aad[12] = casket::get_byte<1>(inputLength);

    auto tagLength = EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_AEAD_TLS1_AAD, static_cast<int>(aad.size()),
                                         const_cast<uint8_t*>(aad.data()));
    crypto::ThrowIfFalse(tagLength > 0, "Invalid tag length");

    if (encrypt)
    {
        inputLength += tagLength;
    }

    /// Encryption/Decryption in place
    nonstd::span<uint8_t> out = in;
    auto outputLength = EVP_Cipher(cipherCtx, out.data(), in.data(), static_cast<unsigned int>(inputLength));
    crypto::ThrowIfFalse(outputLength > 0, "Bad record MAC");

    if (!encrypt)
    {
        if (mode == EVP_CIPH_GCM_MODE)
        {
            out = out.subspan(EVP_GCM_TLS_EXPLICIT_IV_LEN);
            outputLength = in.size() - EVP_GCM_TLS_EXPLICIT_IV_LEN - tagLength;
        }
        else if (mode == EVP_CIPH_CCM_MODE)
        {
            out = out.subspan(EVP_CCM_TLS_EXPLICIT_IV_LEN);
            outputLength = in.size() - EVP_CCM_TLS_EXPLICIT_IV_LEN - tagLength;
        }
        else
        {
            outputLength = in.size() - tagLength;
        }
    }

    return {out.data(), static_cast<size_t>(outputLength)};
}

nonstd::span<uint8_t> RecordLayer::doTLSv1Process(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx,
                                                  const Hash* hmacHash, RecordType rt, uint64_t seq,
                                                  nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> macKey,
                                                  nonstd::span<const uint8_t> iv, nonstd::span<const uint8_t> in,
                                                  nonstd::span<uint8_t> out, bool encrypt)
{
    nonstd::span<std::uint8_t> decryptedContent;

    (void)encrypt;

    /* Block cipher */
    if (CipherTraits::getBlockLength(cipherCtx) > 1)
    {
        auto outSize = in.size();

        if (encryptThenMAC_)
        {
            auto mac = in.subspan(in.size() - HashTraits::getSize(hmacHash));

            outSize -= mac.size();
            auto cipherText = in.subspan(0, outSize);

            crypto::ThrowIfFalse(0 < EVP_Cipher(cipherCtx, out.data(), cipherText.data(), cipherText.size()));

            uint8_t paddingLength = out[outSize - 1];
            paddingLength += 1;
            casket::ThrowIfTrue(paddingLength > outSize, "Invalid padding length");
            outSize -= paddingLength;

            if (version_ >= ProtocolVersion::TLSv1_1)
            {
                uint32_t blockSize = CipherTraits::getBlockLength(cipherCtx);
                casket::ThrowIfFalse(blockSize <= outSize, "Block size greater than Plaintext!");

                auto iv = in.subspan(0, blockSize);
                auto content = in.subspan(iv.size(), in.size() - iv.size() - mac.size());
                tls1CheckMac(hmacCtx, hmacHash, rt, seq, macKey, iv, content, mac);

                outSize -= blockSize;
                decryptedContent = {out.data() + iv.size(), outSize};
            }
            else
            {
                auto content = in.subspan(0, in.size() - mac.size());
                tls1CheckMac(hmacCtx, hmacHash, rt, seq, macKey, {}, content, mac);
                decryptedContent = {out.data(), outSize};
            }
        }
        else
        {
            auto cipherText = in.subspan(0, outSize);

            crypto::ThrowIfFalse(0 < EVP_Cipher(cipherCtx, out.data(), cipherText.data(), cipherText.size()));

            uint8_t paddingLength = out[outSize - 1];
            outSize -= (paddingLength + 1);

            auto mac = nonstd::span(out.begin() + outSize - HashTraits::getSize(hmacHash), out.begin() + outSize);
            outSize -= mac.size();

            if (version_ >= ProtocolVersion::TLSv1_1)
            {
                uint32_t blockSize = CipherTraits::getBlockLength(cipherCtx);
                casket::ThrowIfFalse(blockSize <= outSize, "Block size greater than Plaintext!");

                auto content = nonstd::span(out.begin() + blockSize, out.begin() + outSize);
                tls1CheckMac(hmacCtx, hmacHash, rt, seq, macKey, {}, content, mac);

                outSize -= blockSize;
            }
            else
            {
                auto content = nonstd::span(out.begin(), out.begin() + outSize);

                if (version_ == ProtocolVersion::SSLv3_0)
                {
                    ssl3CheckMac(hashCtx, hmacHash, rt, seq, macKey, content, mac);
                }
                else
                {
                    tls1CheckMac(hmacCtx, hmacHash, rt, seq, macKey, {}, content, mac);
                }
            }
            decryptedContent = {out.data(), outSize};
        }
    }
    /* Stream cipher */
    else if (CipherTraits::getBlockLength(cipherCtx) == 1)
    {
        crypto::ThrowIfFalse(0 < EVP_CipherInit(cipherCtx, nullptr, key.data(), iv.data(), 0));
        crypto::ThrowIfFalse(0 < EVP_Cipher(cipherCtx, out.data(), in.data(), in.size()));

        auto content = nonstd::span(out.begin(), out.end() - HashTraits::getSize(hmacHash));
        auto mac = nonstd::span(out.end() - HashTraits::getSize(hmacHash), out.end());

        if (version_ == ProtocolVersion::SSLv3_0)
        {
            ssl3CheckMac(hashCtx, hmacHash, rt, seq, macKey, content, mac);
        }
        else
        {
            tls1CheckMac(hmacCtx, hmacHash, rt, seq, macKey, {}, content, mac);
        }

        decryptedContent = {out.data(), in.size() - mac.size()};
    }

    return decryptedContent;
}

void RecordLayer::tls1CheckMac(MacCtx* hmacCtx, const Hash* hmacHash, const RecordType recordType, uint64_t seq,
                               nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv,
                               nonstd::span<const uint8_t> content, nonstd::span<const uint8_t> expectedMac)
{
    std::array<uint8_t, 13> meta;
    casket::store_be(seq, meta.data());

    meta[8] = static_cast<uint8_t>(recordType);
    meta[9] = version_.majorVersion();
    meta[10] = version_.minorVersion();
    uint16_t s = content.size() + iv.size();
    meta[11] = casket::get_byte<0>(s);
    meta[12] = casket::get_byte<1>(s);

    HmacTraits::initHmac(hmacCtx, hmacHash, macKey);
    HmacTraits::updateHmac(hmacCtx, meta);

    if (!iv.empty())
    {
        HmacTraits::updateHmac(hmacCtx, iv);
    }

    HmacTraits::updateHmac(hmacCtx, content);

    std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
    auto actualMac = HmacTraits::finalHmac(hmacCtx, buffer);

    casket::ThrowIfFalse(expectedMac.size() == actualMac.size() &&
                             std::equal(expectedMac.begin(), expectedMac.end(), actualMac.begin()),
                         "Bad record MAC");
}

void RecordLayer::ssl3CheckMac(HashCtx* ctx, const Hash* hmacHash, RecordType recordType, uint64_t seq,
                               nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> content,
                               nonstd::span<const uint8_t> expectedMac)
{
    size_t paddingSize = crypto::HashTraits::isAlgorithm(hmacHash, "SHA1") ? 40 : 48;

    HashTraits::hashInit(ctx, hmacHash);
    HashTraits::hashUpdate(ctx, macKey);

    uint8_t padding[64];
    memset(padding, 0x36, paddingSize);
    HashTraits::hashUpdate(ctx, {padding, paddingSize});

    std::array<uint8_t, 11> meta;
    casket::store_be(seq, meta.data());

    meta[8] = static_cast<uint8_t>(recordType);
    uint16_t s = content.size();
    meta[9] = casket::get_byte<0>(s);
    meta[10] = casket::get_byte<1>(s);

    std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;

    HashTraits::hashUpdate(ctx, meta);
    HashTraits::hashUpdate(ctx, content);
    auto preActualMac = HashTraits::hashFinal(ctx, buffer);

    HashTraits::hashInit(ctx, hmacHash);
    HashTraits::hashUpdate(ctx, macKey);

    memset(padding, 0x5c, paddingSize);
    HashTraits::hashUpdate(ctx, {padding, paddingSize});
    HashTraits::hashUpdate(ctx, preActualMac);
    auto actualMac = HashTraits::hashFinal(ctx, buffer);

    casket::ThrowIfFalse(expectedMac.size() == actualMac.size() &&
                             std::equal(expectedMac.begin(), expectedMac.end(), actualMac.begin()),
                         "Bad record MAC");
}

void RecordLayer::doTLSv13Encrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq, nonstd::span<const uint8_t> key,
                                  nonstd::span<const uint8_t> iv)
{
    assert(record->ciphertextBuffer_.size() >= record->plaintext_.size() + 1 + tagLength_);

    record->plaintext_ = record->plaintext_.first(record->plaintext_.size() + 1);
    record->plaintext_.back() = static_cast<uint8_t>(record->getType());

    nonstd::span<uint8_t> ciphertext = record->ciphertextBuffer_;
    auto encryptedData = doTLSv13Process(cipherCtx, record->getType(), seq, key, iv, record->plaintext_,
                                         ciphertext.subspan(TLS_HEADER_SIZE), true);

    record->type_ = RecordType::ApplicationData;
    record->ciphertext_ = {ciphertext.data(), TLS_HEADER_SIZE + encryptedData.size()};
    record->isDecrypted_ = false;
}

void RecordLayer::doTLSv13Decrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq, nonstd::span<const uint8_t> key,
                                  nonstd::span<const uint8_t> iv)
{
    assert(record->getCiphertext().size() > TLS_HEADER_SIZE);

    casket::ThrowIfTrue(record->getType() != RecordType::ApplicationData,
                        "TLSv1.3 encrypted record must have outer type ApplicationData");

    auto input = record->getCiphertext();
    record->plaintext_ = doTLSv13Process(cipherCtx, record->getType(), seq, key, iv, input.subspan(TLS_HEADER_SIZE),
                                         record->plaintextBuffer_, false);

    uint8_t lastByte = record->plaintext_.back();
    casket::ThrowIfTrue(lastByte < 20 || lastByte > 23, "TLSv1.3 record type had unexpected value '{}'", lastByte);

    record->type_ = static_cast<RecordType>(lastByte);
    record->plaintext_ = record->plaintext_.first(record->plaintext_.size() - 1);
    record->isDecrypted_ = true;
}

nonstd::span<std::uint8_t> RecordLayer::doTLSv13Process(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                                        nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv,
                                                        nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out,
                                                        bool encrypt)
{
    int updateLength = 0;
    int finalLength = 0;
    std::array<uint8_t, TLS13_AEAD_AAD_SIZE> aad;
    std::array<uint8_t, TLS13_AEAD_NONCE_SIZE> nonce;

    casket::ThrowIfFalse(iv.size() >= TLS13_AEAD_NONCE_SIZE, "Invalid IV size");
    std::copy_n(iv.begin(), TLS13_AEAD_NONCE_SIZE, nonce.begin());

    assert(tagLength_ > 0);

    for (int i = 0; i < 8; ++i)
    {
        nonce[TLS13_AEAD_NONCE_SIZE - 1 - i] ^= ((seq >> (i * 8)) & 0xFF);
    }

    if (CipherTraits::getMode(cipherCtx) == EVP_CIPH_CCM_MODE)
    {
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_AEAD_SET_IVLEN, EVP_CCM_TLS_IV_LEN, nullptr));
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_AEAD_SET_TAG, tagLength_, nullptr));
        crypto::ThrowIfFalse(0 <
                             EVP_CipherInit(cipherCtx, nullptr, key.data(), nonce.data(), static_cast<int>(encrypt)));
    }
    else
    {
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr));
        crypto::ThrowIfFalse(0 <
                             EVP_CipherInit(cipherCtx, nullptr, key.data(), nonce.data(), static_cast<int>(encrypt)));
    }

    int dataLength = in.size();
    uint16_t encryptedRecordLength = static_cast<uint16_t>(in.size());

    if (!encrypt)
    {
        /// TLSv1.3 uses 1 byte to denote inner content type.
        casket::ThrowIfFalse(in.size() >= static_cast<size_t>(tagLength_) + 1, "Invalid data size");
        dataLength -= tagLength_;

        /// Set tag for decryption.
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_AEAD_SET_TAG, tagLength_,
                                                     const_cast<uint8_t*>(in.data()) + dataLength));
    }
    else
    {
        /// Calculate size for AAD
        encryptedRecordLength += tagLength_;
    }

    if (CipherTraits::getMode(cipherCtx) == EVP_CIPH_CCM_MODE)
    {
        crypto::ThrowIfFalse(0 < EVP_CipherUpdate(cipherCtx, nullptr, &updateLength, nullptr, dataLength));
    }

    aad[0] = static_cast<uint8_t>(rt);
    aad[1] = 0x03;
    aad[2] = 0x03;
    aad[3] = casket::get_byte<0>(encryptedRecordLength);
    aad[4] = casket::get_byte<1>(encryptedRecordLength);

    crypto::ThrowIfFalse(0 < EVP_CipherUpdate(cipherCtx, nullptr, &updateLength, aad.data(), aad.size()));
    crypto::ThrowIfFalse(0 < EVP_CipherUpdate(cipherCtx, out.data(), &updateLength, in.data(), dataLength));
    crypto::ThrowIfFalse(0 < EVP_CipherFinal(cipherCtx, out.data() + updateLength, &finalLength), "Bad record MAC");

    casket::ThrowIfFalse(dataLength == updateLength + finalLength, "Invalid processed length");

    if (encrypt)
    {
        /// Add the tag
        crypto::ThrowIfFalse(
            0 < EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_AEAD_GET_TAG, tagLength_, out.data() + dataLength));
        dataLength += tagLength_;
    }

    return {out.data(), static_cast<size_t>(dataLength)};
}

} // namespace snet::tls