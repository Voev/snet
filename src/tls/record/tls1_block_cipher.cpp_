#include <snet/tls/record/tls1_block_cipher.hpp>

#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/tls/record/tls1_mac.hpp>

#include <snet/crypto/exception.hpp>

#include <casket/utils/exception.hpp>

namespace snet::tls::v1
{

void BlockCipher::initDecrypt(CipherCtx* cipherctx, const CipherTraits& traits,
                              std::span<const uint8_t> encKey, std::span<const uint8_t> encIV)
{
    auto cipher = CipherSuiteManager::getInstance().fetchCipher(traits.cipherName);
    crypto::ThrowIfFalse(0 < EVP_CipherInit(cipherctx, cipher, encKey.data(), encIV.data(), 0));
}

void BlockCipher::decrypt(CipherCtx* cipherCtx, const CipherTraits& traits,
                          uint64_t seq, RecordType rt, std::span<const uint8_t> in,
                          std::vector<uint8_t>& out, std::span<const uint8_t> macKey)
{
    auto md = CipherSuiteManager::getInstance().fetchDigest(traits.digestName);
    size_t outSize{in.size()};

    if (traits.encryptThenMac)
    {
        auto mac = in.subspan(in.size() - EVP_MD_get_size(md));

        outSize -= mac.size();
        auto cipherText = in.subspan(0, outSize);

        out.resize(cipherText.size());
        crypto::ThrowIfFalse(
            0 < EVP_Cipher(cipherCtx, out.data(), cipherText.data(), cipherText.size()));

        uint8_t paddingLength = out[outSize - 1];
        outSize -= (paddingLength + 1);

        if (traits.version >= ProtocolVersion::TLSv1_1)
        {
            uint32_t blockSize = EVP_CIPHER_CTX_get_block_size(cipherCtx);
            casket::utils::ThrowIfFalse(blockSize <= outSize, "Block size greater than Plaintext!");

            auto iv = in.subspan(0, blockSize);
            auto content = in.subspan(iv.size(), in.size() - iv.size() - mac.size());
            checkTls1Mac(traits, seq, rt, macKey, content, mac, iv);

            out.erase(out.begin(), out.begin() + blockSize);
            outSize -= blockSize;
        }
        else
        {
            auto content = in.subspan(0, in.size() - mac.size());
            checkTls1Mac(traits, seq, rt, macKey, content, mac, {});
        }

        out.resize(outSize);
    }
    else
    {
        auto cipherText = in.subspan(0, outSize);

        out.resize(cipherText.size());
        crypto::ThrowIfFalse(
            0 < EVP_Cipher(cipherCtx, out.data(), cipherText.data(), cipherText.size()));

        uint8_t paddingLength = out[outSize - 1];
        outSize -= (paddingLength + 1);

        auto mac = std::span(out.begin() + outSize - EVP_MD_get_size(md), out.begin() + outSize);
        outSize -= mac.size();

        if (traits.version >= ProtocolVersion::TLSv1_1)
        {
            uint32_t blockSize = EVP_CIPHER_CTX_get_block_size(cipherCtx);
            casket::utils::ThrowIfFalse(blockSize <= outSize, "Block size greater than Plaintext!");

            auto content = std::span(out.begin() + blockSize, out.begin() + outSize);
            checkTls1Mac(traits, seq, rt, macKey, content, mac, {});

            out.erase(out.begin(), out.begin() + blockSize);
            outSize -= blockSize;
        }
        else
        {
            auto content = std::span(out.begin(), out.begin() + outSize);

            if (traits.version == ProtocolVersion::SSLv3_0)
            {
                checkSsl3Mac(traits, seq, rt, macKey, content, mac);
            }
            else
            {
                checkTls1Mac(traits, seq, rt, macKey, content, mac, {});
            }
        }

        out.resize(outSize);
    }
}

} // namespace snet::tls::v1