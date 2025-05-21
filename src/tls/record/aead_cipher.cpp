#include <snet/tls/record/aead_cipher.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::tls
{

void AeadCipher::encryptInit(CipherCtx* ctx, const Cipher* cipher)
{
    crypto::ThrowIfFalse(0 < EVP_EncryptInit(ctx, cipher, nullptr, nullptr));
}

void AeadCipher::encrypt(CipherCtx* ctx, const Cipher* cipher, CipherOperation& op)
{
    int length{0};

    crypto::ThrowIfFalse(0 < EVP_EncryptInit(ctx, cipher, nullptr, nullptr));

    crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, op.ivLength, nullptr));

    crypto::ThrowIfFalse(0 < EVP_EncryptInit(ctx, nullptr, op.key, op.iv));

    crypto::ThrowIfFalse(0 < EVP_EncryptUpdate(ctx, nullptr, &length, op.aad, op.aadLength));

    crypto::ThrowIfFalse(0 < EVP_EncryptUpdate(ctx, op.ciphertext, &length, op.plaintext, op.plaintextLength));

    crypto::ThrowIfFalse(0 < EVP_EncryptFinal_ex(ctx, op.ciphertext + length, &length));

    crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, op.tagLength, op.tag));
}

void AeadCipher::decryptInit(CipherCtx* ctx, const Cipher* cipher)
{
    crypto::ThrowIfFalse(0 < EVP_DecryptInit(ctx, cipher, nullptr, nullptr));
}

void AeadCipher::decrypt(CipherCtx* ctx, CipherOperation& op)
{
    int length{0};

    crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, op.ivLength, nullptr));

    crypto::ThrowIfFalse(0 < EVP_DecryptInit(ctx, nullptr, op.key, op.iv));

    crypto::ThrowIfFalse(0 < EVP_DecryptUpdate(ctx, nullptr, &length, op.aad, op.aadLength));

    crypto::ThrowIfFalse(0 < EVP_DecryptUpdate(ctx, op.plaintext, &length, op.ciphertext, op.ciphertextLength));

    crypto::ThrowIfFalse(0 < EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, op.tagLength, op.tag));

    crypto::ThrowIfFalse(0 < EVP_DecryptFinal_ex(ctx, op.plaintext + length, &length), "Bad record MAC!");
}

} // namespace snet::tls