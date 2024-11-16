#include <snet/log/log_manager.hpp>

#include <openssl/ssl.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <snet/utils/endianness.hpp>
#include <snet/utils/exception.hpp>
#include <snet/utils/hexlify.hpp>
#include <snet/utils/load_store.hpp>

#include <snet/tls/exception.hpp>
#include <snet/tls/record_decoder.hpp>

namespace snet::tls
{

RecordDecoder::RecordDecoder()
    : cipherSuite_()
    , cipher_(EVP_CIPHER_CTX_new())
    , seq_(0)
{
}

RecordDecoder::~RecordDecoder() noexcept
{
}

RecordDecoder::RecordDecoder(CipherSuite cs, std::span<const uint8_t> macKey,
                             std::span<const uint8_t> encKey, std::span<const uint8_t> iv)
    : cipherSuite_(cs)
    , cipher_(EVP_CIPHER_CTX_new())
    , seq_(0)
{

    auto cipher = CipherSuiteManager::Instance().fetchCipher(cipherSuite_.getCipherName());

    implicitIv_.resize(iv.size());
    memcpy(implicitIv_.data(), iv.data(), iv.size());

    writeKey_.resize(encKey.size());
    memcpy(writeKey_.data(), encKey.data(), encKey.size());

    if (cipherSuite_.isAEAD())
    {
        tls::ThrowIfFalse(0 < EVP_CipherInit(cipher_, cipher, nullptr, nullptr, 0));
    }
    else
    {
        macKey_.resize(macKey.size());
        memcpy(macKey_.data(), macKey.data(), macKey.size());
        tls::ThrowIfFalse(0 < EVP_CipherInit(cipher_, cipher, encKey.data(), iv.data(), 0));
    }
}

void RecordDecoder::initAEAD(CipherSuite cs, std::span<const uint8_t> encKey,
                             std::span<const uint8_t> encIV)
{
    cipherSuite_ = cs;

    implicitIv_.resize(encIV.size());
    memcpy(implicitIv_.data(), encIV.data(), encIV.size());

    writeKey_.resize(encKey.size());
    memcpy(writeKey_.data(), encKey.data(), encKey.size());

    auto cipher = CipherSuiteManager::Instance().fetchCipher(cipherSuite_.getCipherName());
    tls::ThrowIfFalse(0 < EVP_CipherInit(cipher_, cipher, nullptr, nullptr, 0));
}

void RecordDecoder::tls13UpdateKeys(const std::vector<uint8_t>& newkey,
                                    const std::vector<uint8_t>& newiv)
{
    std::copy(newkey.begin(), newkey.end(), writeKey_.begin());
    std::copy(newiv.begin(), newiv.end(), implicitIv_.begin());
    seq_ = 0;
}

size_t GetTagLength(EVP_CIPHER_CTX* ctx)
{
    if (EVP_CIPHER_CTX_get_mode(ctx) == EVP_CIPH_CCM_MODE)
    {
        return EVP_CCM_TLS_TAG_LEN;
    }
    return EVP_CIPHER_CTX_get_tag_length(ctx);
}

void RecordDecoder::tls13Decrypt(RecordType rt, std::span<const uint8_t> in,
                                 std::vector<uint8_t>& out)
{
    int i;
    int x;
    std::array<uint8_t, TLS13_AEAD_AAD_SIZE> aad;
    std::array<uint8_t, 12> aead_nonce;

    utils::printHex("CipherText", in);
    utils::printHex("KEY", writeKey_);
    utils::printHex("IV", implicitIv_);

    utils::ThrowIfFalse(cipherSuite_.isAEAD(), "it must be AEAD!");

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
    aad[3] = utils::get_byte<0>(size);
    aad[4] = utils::get_byte<1>(size);

    utils::printHex("NONCE", aead_nonce);
    utils::printHex("Tag", tag);
    utils::printHex("AAD", aad);

    tls::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr));

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_CCM_MODE)
    {
        tls::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_TAG, tag.size(),
                                                  const_cast<uint8_t*>(tag.data())));
    }

    tls::ThrowIfFalse(
        0 < EVP_DecryptInit_ex(cipher_, nullptr, nullptr, writeKey_.data(), aead_nonce.data()));

    int outSize{0};

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_CCM_MODE)
    {
        tls::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, nullptr, &outSize, nullptr, data.size()));
    }

    tls::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, nullptr, &outSize, aad.data(), aad.size()));

    outSize = data.size();
    out.resize(outSize);
    tls::ThrowIfFalse(0 <
                      EVP_DecryptUpdate(cipher_, out.data(), &outSize, data.data(), data.size()));
    out.resize(outSize);

    if (EVP_CIPHER_CTX_get_mode(cipher_) == EVP_CIPH_GCM_MODE)
    {
        tls::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_GCM_SET_TAG, tag.size(),
                                                  const_cast<uint8_t*>(tag.data())));
        tls::ThrowIfFalse(0 < EVP_DecryptFinal(cipher_, nullptr, &x));
    }
}

void RecordDecoder::tls1Decrypt(RecordType rt, ProtocolVersion version, std::span<const uint8_t> in,
                                std::vector<uint8_t>& out, bool encryptThenMac)
{
    if (cipherSuite_.isAEAD())
    {
        uint8_t aad[TLS12_AEAD_AAD_SIZE];

        auto recordIvSize = EVP_CIPHER_CTX_get_iv_length(cipher_);
        std::vector<uint8_t> aead_nonce;

        aead_nonce.reserve(recordIvSize);
        aead_nonce.insert(aead_nonce.end(), implicitIv_.begin(), implicitIv_.end());

        auto recordIv = in.subspan(0, recordIvSize - implicitIv_.size());
        in = in.subspan(recordIv.size());

        aead_nonce.insert(aead_nonce.end(), recordIv.begin(), recordIv.end());

        tls::ThrowIfFalse(0 <
                          EVP_DecryptInit(cipher_, nullptr, writeKey_.data(), aead_nonce.data()));

        auto tagLength = GetTagLength(cipher_);
        auto data = in.subspan(0, in.size() - tagLength);
        auto tag = in.subspan(in.size() - tagLength, tagLength);

        tls::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipher_, EVP_CTRL_AEAD_SET_TAG,
                                                  static_cast<int>(tag.size()),
                                                  const_cast<uint8_t*>(tag.data())));

        utils::store_be(seq_, &aad[0]);
        aad[8] = static_cast<uint8_t>(rt);
        aad[9] = version.majorVersion();
        aad[10] = version.minorVersion();
        uint16_t size = static_cast<uint16_t>(data.size());
        aad[11] = utils::get_byte<0>(size);
        aad[12] = utils::get_byte<1>(size);

        seq_++;

        utils::printHex("AEAD Tag", tag);
        utils::printHex("AEAD Nonce", aead_nonce);
        utils::printHex("CipherText", data);

        int outSize{0};
        tls::ThrowIfFalse(0 < EVP_DecryptUpdate(cipher_, nullptr, &outSize, aad, sizeof(aad)));

        outSize = out.size();
        out.resize(outSize);

        tls::ThrowIfFalse(
            0 < EVP_DecryptUpdate(cipher_, out.data(), &outSize, data.data(), data.size()));
        out.resize(outSize);

        int x{0};
        tls::ThrowIfFalse(0 < EVP_DecryptFinal(cipher_, nullptr, &x));
    }
    /* Block cipher */
    else if (EVP_CIPHER_CTX_get_block_size(cipher_) > 1)
    {
        auto md = CipherSuiteManager::Instance().fetchDigest(cipherSuite_.getDigestName());
        size_t outSize{in.size()};

        if (encryptThenMac)
        {
            auto mac = in.subspan(in.size() - EVP_MD_get_size(md));

            outSize -= mac.size();
            auto cipherText = in.subspan(0, outSize);

            out.resize(cipherText.size());
            tls::ThrowIfFalse(
                0 < EVP_Cipher(cipher_, out.data(), cipherText.data(), cipherText.size()));

            uint8_t paddingLength = out[outSize - 1];
            outSize -= (paddingLength + 1);

            if (version >= ProtocolVersion::TLSv1_1)
            {
                uint32_t blockSize = EVP_CIPHER_CTX_get_block_size(cipher_);
                utils::ThrowIfFalse(blockSize <= outSize, "Block size greater than Plaintext!");

                auto iv = in.subspan(0, blockSize);
                auto content = in.subspan(iv.size(), in.size() - iv.size() - mac.size());
                tls1CheckMac(rt, version, iv, content, mac);

                out.erase(out.begin(), out.begin() + blockSize);
                outSize -= blockSize;
            }
            else
            {
                auto content = in.subspan(0, in.size() - mac.size());
                tls1CheckMac(rt, version, {}, content, mac);
            }

            out.resize(outSize);
        }
        else
        {
            auto cipherText = in.subspan(0, outSize);

            out.resize(cipherText.size());
            tls::ThrowIfFalse(
                0 < EVP_Cipher(cipher_, out.data(), cipherText.data(), cipherText.size()));

            uint8_t paddingLength = out[outSize - 1];
            outSize -= (paddingLength + 1);

            auto mac =
                std::span(out.begin() + outSize - EVP_MD_get_size(md), out.begin() + outSize);
            outSize -= mac.size();

            if (version >= ProtocolVersion::TLSv1_1)
            {
                uint32_t blockSize = EVP_CIPHER_CTX_get_block_size(cipher_);
                utils::ThrowIfFalse(blockSize <= outSize, "Block size greater than Plaintext!");

                auto content = std::span(out.begin() + blockSize, out.begin() + outSize);
                tls1CheckMac(rt, version, {}, content, mac);

                out.erase(out.begin(), out.begin() + blockSize);
                outSize -= blockSize;
            }
            else
            {
                auto content = std::span(out.begin(), out.begin() + outSize);

                if (version == ProtocolVersion::SSLv3_0)
                {
                    ssl3CheckMac(rt, content, mac);
                }
                else
                {
                    tls1CheckMac(rt, version, {}, content, mac);
                }
            }

            out.resize(outSize);
        }
    }
    /* Stream cipher */
    else if (EVP_CIPHER_CTX_get_block_size(cipher_) == 1)
    {
        auto md = CipherSuiteManager::Instance().fetchDigest(cipherSuite_.getDigestName());
        size_t outSize{in.size()};

        out.resize(outSize);
        tls::ThrowIfFalse(0 < EVP_Cipher(cipher_, out.data(), in.data(), in.size()));

        auto content = std::span(out.begin(), out.end() - EVP_MD_get_size(md));
        auto mac = std::span(out.end() - EVP_MD_get_size(md), out.end());
        if (version == ProtocolVersion::SSLv3_0)
        {
            ssl3CheckMac(rt, content, mac);
        }
        else
        {
            tls1CheckMac(rt, version, {}, content, mac);
        }

        outSize -= mac.size();
        out.resize(outSize);
    }
}

void RecordDecoder::tls1CheckMac(RecordType recordType, ProtocolVersion version,
                                 std::span<const uint8_t> iv, std::span<const uint8_t> content,
                                 std::span<const uint8_t> expectedMac)
{
    std::array<uint8_t, 13> meta;
    utils::store_be(seq_, meta.data());
    seq_++;
    meta[8] = static_cast<uint8_t>(recordType);
    meta[9] = version.majorVersion();
    meta[10] = version.minorVersion();
    uint16_t s = content.size() + iv.size();
    meta[11] = utils::get_byte<0>(s);
    meta[12] = utils::get_byte<1>(s);

    auto digest = cipherSuite_.getDigestName();

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 const_cast<char*>(digest.c_str()), 0);
    params[1] = OSSL_PARAM_construct_end();

    auto mac = CipherSuiteManager::Instance().fetchMac("HMAC");

    EvpMacCtxPtr ctx(EVP_MAC_CTX_new(mac));
    tls::ThrowIfTrue(ctx == nullptr);

    tls::ThrowIfFalse(0 < EVP_MAC_CTX_set_params(ctx, params));
    tls::ThrowIfFalse(0 < EVP_MAC_init(ctx, macKey_.data(), macKey_.size(), nullptr));
    tls::ThrowIfFalse(0 < EVP_MAC_update(ctx, meta.data(), meta.size()));

    if (!iv.empty())
    {
        tls::ThrowIfFalse(0 < EVP_MAC_update(ctx, iv.data(), iv.size()));
    }

    tls::ThrowIfFalse(0 < EVP_MAC_update(ctx, content.data(), content.size()));

    size_t actualMacSize{EVP_MAX_MD_SIZE};
    std::vector<uint8_t> actualMac(actualMacSize);
    tls::ThrowIfFalse(0 < EVP_MAC_final(ctx, actualMac.data(), &actualMacSize, actualMacSize));

    actualMac.resize(actualMacSize);

    utils::ThrowIfFalse(std::equal(expectedMac.begin(), expectedMac.end(), actualMac.begin()),
                        "Bad record MAC");
}

void RecordDecoder::ssl3CheckMac(RecordType recordType, std::span<const uint8_t> content,
                                 std::span<const uint8_t> mac)
{
    unsigned int actualMacSize{EVP_MAX_MD_SIZE};
    std::vector<uint8_t> actualMac(actualMacSize);

    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    tls::ThrowIfFalse(ctx != nullptr);

    auto md = CipherSuiteManager::Instance().fetchDigest(cipherSuite_.getDigestName());
    tls::ThrowIfFalse(md != nullptr);

    int pad_ct = EVP_MD_is_a(md, "SHA1") > 0 ? 40 : 48;

    tls::ThrowIfFalse(0 < EVP_DigestInit(ctx, md));
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, macKey_.data(), macKey_.size()));

    uint8_t buf[64];
    memset(buf, 0x36, pad_ct);
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, buf, pad_ct));

    std::array<uint8_t, 11> meta;
    utils::store_be(seq_, meta.data());
    seq_++;
    meta[8] = static_cast<uint8_t>(recordType);
    uint16_t s = content.size();
    meta[9] = utils::get_byte<0>(s);
    meta[10] = utils::get_byte<1>(s);

    tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, meta.data(), meta.size()));
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, content.data(), content.size()));
    tls::ThrowIfFalse(0 < EVP_DigestFinal(ctx, actualMac.data(), &actualMacSize));

    actualMac.resize(actualMacSize);

    tls::ThrowIfFalse(0 < EVP_DigestInit(ctx, md));
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, macKey_.data(), macKey_.size()));

    memset(buf, 0x5c, pad_ct);
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, buf, pad_ct));
    tls::ThrowIfFalse(0 < EVP_DigestUpdate(ctx, actualMac.data(), actualMacSize));
    tls::ThrowIfFalse(0 < EVP_DigestFinal(ctx, actualMac.data(), &actualMacSize));

    actualMac.resize(actualMacSize);

    utils::ThrowIfFalse(std::equal(mac.begin(), mac.end(), actualMac.begin()), "Bad record MAC");
}

} // namespace snet::tls