#include <cassert>
#include <cstring>

#include <casket/utils/exception.hpp>
#include <casket/utils/load_store.hpp>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/cipher_traits.hpp>
#include <snet/crypto/hash_traits.hpp>
#include <snet/crypto/hmac_traits.hpp>

#include <snet/tls/record_layer.hpp>

using namespace casket;
using namespace snet::crypto;

namespace snet::tls
{

void RecordLayer::encrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, Record* record,
                          uint64_t seq, nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv)
{
    if (version_ == ProtocolVersion::TLSv1_3)
    {
        doTLSv13Encrypt(cipherCtx, record, seq, iv);
    }
    else if (aead_)
    {
        doTLSv1AeadEncrypt(cipherCtx, record, seq);
    }
    else
    {
        doTLSv1Encrypt(cipherCtx, hmacCtx, hashCtx, hmacHash, record, seq, macKey);
    }
}

void RecordLayer::decrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, Record* record,
                          uint64_t seq, nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv)
{
    if (version_ == ProtocolVersion::TLSv1_3)
    {
        doTLSv13Decrypt(cipherCtx, record, seq, iv);
    }
    else if (aead_)
    {
        doTLSv1AeadDecrypt(cipherCtx, record, seq);
    }
    else
    {
        doTLSv1Decrypt(cipherCtx, hmacCtx, hashCtx, hmacHash, record, seq, macKey);
    }
}

void RecordLayer::init(CipherCtx* ctx, const Cipher* cipher, nonstd::span<const uint8_t> key,
                       nonstd::span<const uint8_t> iv, bool encrypt)
{
    ThrowIfFalse(0 < EVP_CipherInit(ctx, cipher, key.data(), iv.data(), static_cast<int>(encrypt)));
}

nonstd::span<const uint8_t> RecordLayer::tls1ComputeMac(MacCtx* hmacCtx, const Hash* hmacHash, RecordType rt,
                                                        uint64_t seq, nonstd::span<const uint8_t> macKey,
                                                        nonstd::span<const uint8_t> iv,
                                                        nonstd::span<const uint8_t> content, nonstd::span<uint8_t> out)
{
    std::array<uint8_t, 13> meta;
    casket::store_be(seq, meta.data());
    meta[8] = static_cast<uint8_t>(rt);
    meta[9] = version_.majorVersion();
    meta[10] = version_.minorVersion();
    const uint16_t s = static_cast<uint16_t>(content.size() + iv.size());
    meta[11] = casket::get_byte<0>(s);
    meta[12] = casket::get_byte<1>(s);

    HmacTraits::initHmac(hmacCtx, hmacHash, macKey);
    HmacTraits::updateHmac(hmacCtx, meta);
    if (!iv.empty())
        HmacTraits::updateHmac(hmacCtx, iv);
    HmacTraits::updateHmac(hmacCtx, content);
    return HmacTraits::finalHmac(hmacCtx, out);
}

void RecordLayer::tls1CheckMac(MacCtx* hmacCtx, const Hash* hmacHash, RecordType recordType, uint64_t seq,
                               nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv,
                               nonstd::span<const uint8_t> content, nonstd::span<const uint8_t> expectedMac)
{
    std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
    const auto actualMac = tls1ComputeMac(hmacCtx, hmacHash, recordType, seq, macKey, iv, content, buffer);
    casket::ThrowIfFalse(
        expectedMac.size() == actualMac.size() && std::equal(expectedMac.begin(), expectedMac.end(), actualMac.begin()),
        "Bad record MAC");
}
void RecordLayer::doTLSv1Encrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* /*hashCtx*/, const Hash* hmacHash,
                                 Record* record, uint64_t seq, nonstd::span<const uint8_t> macKey)
{
    casket::ThrowIfTrue(version_ == ProtocolVersion::SSLv3_0, "SSL 3.0 record encryption is not implemented");

    const auto plaintext = record->getPlaintext();
    const auto type = record->getType();
    const auto blockSize = CipherTraits::getBlockLength(cipherCtx);
    const auto macSize = HashTraits::getSize(hmacHash);
    const bool tls11plus = version_ >= ProtocolVersion::TLSv1_1;
    const size_t explicitIV = (tls11plus && blockSize > 1) ? blockSize : 0u;

    auto out = record->mutableCiphertextBuffer();
    size_t outSize = 0;

    auto generateAndPrependIV = [&]()
    {
        std::array<uint8_t, EVP_MAX_IV_LENGTH> ivBuf;
        crypto::ThrowIfFalse(RAND_bytes(ivBuf.data(), static_cast<int>(blockSize)) > 0, "Failed to generate IV");
        crypto::ThrowIfFalse(0 < EVP_CipherInit_ex(cipherCtx, nullptr, nullptr, nullptr, ivBuf.data(), 1),
                             "Failed to set IV");
        std::memcpy(out.data(), ivBuf.data(), blockSize);
    };

    if (blockSize == 1)
    {
        // Stream cipher: content || MAC, then encrypt
        casket::ThrowIfTrue(plaintext.size() + macSize > out.size(), "Plaintext too large for ciphertext buffer");
        std::memcpy(out.data(), plaintext.data(), plaintext.size());

        const auto mac = tls1ComputeMac(hmacCtx,
                                        hmacHash,
                                        type,
                                        seq,
                                        macKey,
                                        {},
                                        out.first(plaintext.size()),
                                        out.subspan(plaintext.size(), macSize));
        casket::ThrowIfTrue(mac.size() != macSize, "Unexpected MAC size");

        const size_t contentLen = plaintext.size() + macSize;
        crypto::ThrowIfFalse(0 < EVP_Cipher(cipherCtx, out.data(), out.data(), static_cast<unsigned int>(contentLen)));
        outSize = contentLen;
    }
    else if (blockSize > 1)
    {
        if (encryptThenMAC_)
        {
            // Encrypt-then-MAC (RFC 7366)
            // Layout: [IV (1.1+)] [ciphertext(padding||plaintext)] [MAC(IV||ciphertext)]
            const size_t padLen = blockSize - 1 - (plaintext.size() % blockSize);
            const size_t paddedLen = plaintext.size() + padLen + 1;

            casket::ThrowIfTrue(explicitIV + paddedLen + macSize > out.size(), "Ciphertext buffer too small");

            auto enc = out.data() + explicitIV;
            std::memcpy(enc, plaintext.data(), plaintext.size());
            std::memset(enc + plaintext.size(), static_cast<int>(padLen), padLen + 1);

            if (explicitIV > 0)
                generateAndPrependIV();

            crypto::ThrowIfFalse(0 < EVP_Cipher(cipherCtx, enc, enc, static_cast<unsigned int>(paddedLen)));
            outSize = explicitIV + paddedLen;

            const auto mac = tls1ComputeMac(hmacCtx,
                                            hmacHash,
                                            type,
                                            seq,
                                            macKey,
                                            out.first(explicitIV),
                                            out.subspan(explicitIV, paddedLen),
                                            out.subspan(outSize, macSize));
            casket::ThrowIfTrue(mac.size() != macSize, "Unexpected MAC size");
            outSize += macSize;
        }
        else
        {
            // MAC-then-encrypt
            // Layout: [IV (1.1+)] [encrypted(plaintext||MAC||padding)]
            casket::ThrowIfTrue(plaintext.size() + macSize > out.size(), "Plaintext too large for ciphertext buffer");
            std::memcpy(out.data(), plaintext.data(), plaintext.size());

            const auto mac = tls1ComputeMac(hmacCtx,
                                            hmacHash,
                                            type,
                                            seq,
                                            macKey,
                                            {},
                                            out.first(plaintext.size()),
                                            out.subspan(plaintext.size(), macSize));
            casket::ThrowIfTrue(mac.size() != macSize, "Unexpected MAC size");

            const size_t contentLen = plaintext.size() + macSize;
            const size_t padLen = blockSize - 1 - (contentLen % blockSize);
            const size_t paddedLen = contentLen + padLen + 1;

            casket::ThrowIfTrue(explicitIV + paddedLen > out.size(), "Ciphertext buffer too small");
            std::memset(out.data() + contentLen, static_cast<int>(padLen), padLen + 1);

            if (explicitIV > 0)
            {
                std::memmove(out.data() + explicitIV, out.data(), paddedLen);
                generateAndPrependIV();
            }
            crypto::ThrowIfFalse(0 < EVP_Cipher(cipherCtx,
                                                out.data() + explicitIV,
                                                out.data() + explicitIV,
                                                static_cast<unsigned int>(paddedLen)));
            outSize = explicitIV + paddedLen;
        }
    }
    else
    {
        casket::ThrowIfTrue(true, "Unsupported cipher block size");
    }

    record->markEncrypted(out.first(outSize));
}

void RecordLayer::doTLSv1Decrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash,
                                 Record* record, uint64_t seq, nonstd::span<const uint8_t> macKey)
{
    auto input = record->getCiphertext();

    auto plaintext = doTLSv1Process(
        cipherCtx, hmacCtx, hashCtx, hmacHash, record->getType(), seq, macKey, input, record->mutablePlaintextBuffer());

    record->markDecrypted(plaintext);
}

nonstd::span<uint8_t> RecordLayer::doTLSv1Process(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx,
                                                  const Hash* hmacHash, RecordType rt, uint64_t seq,
                                                  nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> in,
                                                  nonstd::span<uint8_t> out)
{
    nonstd::span<std::uint8_t> decryptedContent;

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
                decryptedContent = {out.data() + blockSize, outSize};
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

                decryptedContent = {out.data(), outSize};
            }
        }
    }
    /* Stream cipher */
    else if (CipherTraits::getBlockLength(cipherCtx) == 1)
    {
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

    casket::ThrowIfFalse(
        expectedMac.size() == actualMac.size() && std::equal(expectedMac.begin(), expectedMac.end(), actualMac.begin()),
        "Bad record MAC");
}

void RecordLayer::doTLSv1AeadInit(CipherCtx* ctx, const Cipher* cipher, nonstd::span<const uint8_t> key,
                                  nonstd::span<const uint8_t> iv, bool encrypt)
{
    const auto mode = EVP_CIPHER_mode(cipher);

    if (mode == EVP_CIPH_GCM_MODE)
    {
        uint8_t* ptr = const_cast<uint8_t*>(iv.data());
        ThrowIfFalse(0 < EVP_CipherInit(ctx, cipher, key.data(), nullptr, static_cast<int>(encrypt)));
        ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IV_FIXED, iv.size(), ptr));
    }
    else if (mode == EVP_CIPH_CCM_MODE)
    {
        uint8_t* ptr = const_cast<uint8_t*>(iv.data());
        ThrowIfFalse(0 < EVP_CipherInit(ctx, cipher, nullptr, nullptr, static_cast<int>(encrypt)));
        ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_CCM_SET_IV_FIXED, iv.size(), ptr));
        ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, EVP_CCM_TLS_IV_LEN, nullptr));
        ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLength_, nullptr));
        ThrowIfFalse(0 < EVP_CipherInit(ctx, nullptr, key.data(), nullptr, -1));
    }
    else
    {
        ThrowIfFalse(0 < EVP_CipherInit(ctx, cipher, key.data(), iv.data(), static_cast<int>(encrypt)));
    }
}

void RecordLayer::doTLSv1AeadEncrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq)
{
    auto input = record->mutablePlaintext();
    auto ciphertext = doTLSv1AeadProcess(cipherCtx, record->getType(), seq, input, true);
    record->markEncrypted(ciphertext);
}

void RecordLayer::doTLSv1AeadDecrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq)
{
    auto input = record->mutableCiphertext();
    auto plaintext = doTLSv1AeadProcess(cipherCtx, record->getType(), seq, input, false);
    record->markDecrypted(plaintext);
}

nonstd::span<uint8_t> RecordLayer::doTLSv1AeadProcess(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                                      nonstd::span<uint8_t> in, bool encrypt)
{
    uint16_t inputLength = in.size();

    std::array<uint8_t, TLS12_AEAD_AAD_SIZE> aad;
    casket::store_be(seq, &aad[0]);

    aad[8] = static_cast<uint8_t>(rt);
    aad[9] = version_.majorVersion();
    aad[10] = version_.minorVersion();
    aad[11] = casket::get_byte<0>(inputLength);
    aad[12] = casket::get_byte<1>(inputLength);

    auto tagLength = EVP_CIPHER_CTX_ctrl(
        cipherCtx, EVP_CTRL_AEAD_TLS1_AAD, static_cast<int>(aad.size()), const_cast<uint8_t*>(aad.data()));
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
        const auto mode = CipherTraits::getMode(cipherCtx);

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

void RecordLayer::doTLSv13AeadInit(CipherCtx* ctx, const Cipher* cipher, nonstd::span<const uint8_t> key, bool encrypt)
{
    const auto mode = EVP_CIPHER_mode(cipher);

    if (mode == EVP_CIPH_CCM_MODE)
    {
        ThrowIfFalse(0 < EVP_CipherInit(ctx, cipher, nullptr, nullptr, static_cast<int>(encrypt)));
        ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, EVP_CCM_TLS_IV_LEN, nullptr));
        ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tagLength_, nullptr));
        ThrowIfFalse(0 < EVP_CipherInit(ctx, nullptr, key.data(), nullptr, -1));
    }
    else
    {
        ThrowIfFalse(0 < EVP_CipherInit(ctx, cipher, nullptr, nullptr, static_cast<int>(encrypt)));
        ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr));
        ThrowIfFalse(0 < EVP_CipherInit(ctx, nullptr, key.data(), nullptr, -1));
    }
}

void RecordLayer::doTLSv13KeyUpdate(CipherCtx* ctx, nonstd::span<const uint8_t> key)
{
    ThrowIfFalse(0 < EVP_CipherInit(ctx, nullptr, key.data(), nullptr, -1));
}

void RecordLayer::doTLSv13Encrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq, nonstd::span<const uint8_t> iv)
{
    assert(record->mutableCiphertextBuffer().size() >=
           record->getPlaintext().size() + 1 + static_cast<size_t>(tagLength_));

    auto buf = record->mutablePlaintextBuffer();
    auto pt = record->getPlaintext();
    buf[pt.size()] = static_cast<uint8_t>(record->getType());
    record->setWireType(RecordType::ApplicationData);
    record->setPlaintextLength(pt.size() + 1);

    auto ciphertext = record->mutableCiphertextBuffer();
    auto enc = doTLSv13Process(cipherCtx, record->getType(), seq, iv, record->getPlaintext(), ciphertext, true);
    record->markEncrypted(enc);
}

void RecordLayer::doTLSv13Decrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq, nonstd::span<const uint8_t> iv)
{
    casket::ThrowIfTrue(record->getType() != RecordType::ApplicationData,
                        "TLSv1.3 encrypted record must have outer type ApplicationData");

    auto input = record->getCiphertext();
    auto pt = doTLSv13Process(cipherCtx, record->getType(), seq, iv, input, record->mutablePlaintextBuffer(), false);
    record->markDecrypted(pt);

    uint8_t lastByte = record->getPlaintext().back();
    casket::ThrowIfTrue(lastByte < 20 || lastByte > 23, "TLSv1.3 record type had unexpected value '{}'", lastByte);
    record->setWireType(static_cast<RecordType>(lastByte));
    record->setPlaintextLength(pt.size() - 1);
}

nonstd::span<std::uint8_t> RecordLayer::doTLSv13Process(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                                        nonstd::span<const uint8_t> iv, nonstd::span<const uint8_t> in,
                                                        nonstd::span<uint8_t> out, bool encrypt)
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

    crypto::ThrowIfFalse(0 < EVP_CipherInit(cipherCtx, nullptr, nullptr, nonce.data(), static_cast<int>(encrypt)));

    int dataLength = in.size();
    uint16_t encryptedRecordLength = static_cast<uint16_t>(in.size());

    if (!encrypt)
    {
        /// TLSv1.3 uses 1 byte to denote inner content type.
        casket::ThrowIfFalse(in.size() >= static_cast<size_t>(tagLength_) + 1, "Invalid data size");
        dataLength -= tagLength_;

        /// Set tag for decryption.
        crypto::ThrowIfFalse(
            0 < EVP_CIPHER_CTX_ctrl(
                    cipherCtx, EVP_CTRL_AEAD_SET_TAG, tagLength_, const_cast<uint8_t*>(in.data()) + dataLength));
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