#include <snet/tls/record/tls13_aead_cipher.hpp>
#include <snet/tls/record/cipher_traits.hpp>

#include <snet/tls/cipher_suite_manager.hpp>

#include <snet/utils/load_store.hpp>
#include <snet/utils/print_hex.hpp>

#include <snet/crypto/exception.hpp>

namespace snet::tls::v13
{

void AeadCipher::initDecrypt(CipherCtx* ctx, const CipherTraits& traits,
                             std::span<const uint8_t> encKey)
{
    auto cipher = CipherSuiteManager::getInstance().fetchCipher(traits.cipherName);
    crypto::ThrowIfFalse(0 < EVP_DecryptInit(ctx, cipher, encKey.data(), nullptr));
}

void AeadCipher::decrypt(CipherCtx* ctx, const CipherTraits& traits, uint64_t seq, RecordType rt,
                         std::span<const uint8_t> in, std::vector<uint8_t>& out,
                         std::span<const uint8_t> implicitIV)
{
    (void)traits;

    std::array<uint8_t, TLS13_AEAD_AAD_SIZE> aad;
    std::array<uint8_t, TLS13_AEAD_NONCE_SIZE> aead_nonce;

    utils::printHex(std::cout, "CipherText", in);

    memcpy(aead_nonce.data(), implicitIV.data(), implicitIV.size());

    for (int i = 0; i < 8; ++i)
    {
        aead_nonce[TLS13_AEAD_NONCE_SIZE - 1 - i] ^= ((seq >> (i * 8)) & 0xFF);
    }

    auto tagLength = GetTagLength(ctx);
    auto data = in.subspan(0, in.size() - tagLength);
    auto tag = in.subspan(in.size() - tagLength, tagLength);

    aad[0] = static_cast<uint8_t>(rt);
    aad[1] = 0x03;
    aad[2] = 0x03;
    uint16_t size = static_cast<uint16_t>(in.size());
    aad[3] = utils::get_byte<0>(size);
    aad[4] = utils::get_byte<1>(size);

    utils::printHex(std::cout, "NONCE", aead_nonce);
    utils::printHex(std::cout, "Tag", tag);
    utils::printHex(std::cout, "AAD", aad);

    crypto::ThrowIfFalse(
        0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, TLS13_AEAD_NONCE_SIZE, nullptr));

    if (EVP_CIPHER_CTX_get_mode(ctx) == EVP_CIPH_CCM_MODE)
    {
        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, tag.size(),
                                                     const_cast<uint8_t*>(tag.data())));
    }

    crypto::ThrowIfFalse(0 < EVP_DecryptInit_ex(ctx, nullptr, nullptr, nullptr, aead_nonce.data()));

    int outSize{0};

    if (EVP_CIPHER_CTX_get_mode(ctx) == EVP_CIPH_CCM_MODE)
    {
        crypto::ThrowIfFalse(0 < EVP_DecryptUpdate(ctx, nullptr, &outSize, nullptr, data.size()));
    }

    crypto::ThrowIfFalse(0 < EVP_DecryptUpdate(ctx, nullptr, &outSize, aad.data(), aad.size()));

    outSize = data.size();
    out.resize(outSize);
    crypto::ThrowIfFalse(0 <
                         EVP_DecryptUpdate(ctx, out.data(), &outSize, data.data(), data.size()));
    out.resize(outSize);

    if (EVP_CIPHER_CTX_get_mode(ctx) == EVP_CIPH_GCM_MODE)
    {

        crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(),
                                                     const_cast<uint8_t*>(tag.data())));
        int x;
        crypto::ThrowIfFalse(0 < EVP_DecryptFinal(ctx, nullptr, &x));
    }
}

} // namespace snet::tls::v13