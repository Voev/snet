#include <snet/tls/record/tls1_aead_cipher.hpp>
#include <snet/tls/record/cipher_traits.hpp>

#include <snet/tls/cipher_suite_manager.hpp>

#include <snet/utils/load_store.hpp>
#include <snet/utils/print_hex.hpp>

#include <snet/crypto/exception.hpp>

namespace snet::tls::v1
{

void AeadCipher::initDecrypt(CipherCtx* ctx, const CipherTraits& traits,
                             std::span<const uint8_t> encKey)
{
    auto cipher = CipherSuiteManager::getInstance().fetchCipher(traits.cipherName);
    crypto::ThrowIfFalse(0 < EVP_DecryptInit(ctx, cipher, encKey.data(), nullptr));
}

void AeadCipher::decrypt(CipherCtx* cipherCtx, const CipherTraits& traits, uint64_t seq,
                         RecordType rt, std::span<const uint8_t> in, std::vector<uint8_t>& out,
                         std::span<const uint8_t> implicitIV)
{
    uint8_t aad[TLS12_AEAD_AAD_SIZE];

    auto recordIvSize = EVP_CIPHER_CTX_get_iv_length(cipherCtx);
    std::vector<uint8_t> aead_nonce;
    aead_nonce.reserve(recordIvSize);
    aead_nonce.insert(aead_nonce.end(), implicitIV.begin(), implicitIV.end());

    auto recordIv = in.subspan(0, recordIvSize - implicitIV.size());
    in = in.subspan(recordIv.size());

    aead_nonce.insert(aead_nonce.end(), recordIv.begin(), recordIv.end());

    crypto::ThrowIfFalse(0 < EVP_DecryptInit(cipherCtx, nullptr, nullptr, aead_nonce.data()));

    auto tagLength = GetTagLength(cipherCtx);
    auto data = in.subspan(0, in.size() - tagLength);
    auto tag = in.subspan(in.size() - tagLength, tagLength);

    crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(cipherCtx, EVP_CTRL_AEAD_SET_TAG,
                                                 static_cast<int>(tag.size()),
                                                 const_cast<uint8_t*>(tag.data())));

    utils::store_be(seq, &aad[0]);
    aad[8] = static_cast<uint8_t>(rt);
    aad[9] = traits.version.majorVersion();
    aad[10] = traits.version.minorVersion();
    uint16_t size = static_cast<uint16_t>(data.size());
    aad[11] = utils::get_byte<0>(size);
    aad[12] = utils::get_byte<1>(size);

    utils::printHex(std::cout, "AEAD Tag", tag);
    utils::printHex(std::cout, "AEAD Nonce", aead_nonce);
    utils::printHex(std::cout, "CipherText", data);

    int outSize{0};
    crypto::ThrowIfFalse(0 < EVP_DecryptUpdate(cipherCtx, nullptr, &outSize, aad, sizeof(aad)));

    out.resize(MAX_PLAINTEXT_SIZE);
    outSize = out.size();

    crypto::ThrowIfFalse(
        0 < EVP_DecryptUpdate(cipherCtx, out.data(), &outSize, data.data(), data.size()));

    out.resize(outSize);

    int x{0};
    crypto::ThrowIfFalse(0 < EVP_DecryptFinal(cipherCtx, nullptr, &x));
}

} // namespace snet::tls::v1