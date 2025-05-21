#pragma once
#include <snet/tls/record/cipher_operation.hpp>
#include <snet/crypto/typedefs.hpp>

namespace snet::tls
{

class AeadCipher
{
public:
    static void encryptInit(CipherCtx* ctx, const Cipher* cipher);

    static void encrypt(CipherCtx* ctx, const Cipher* cipher, CipherOperation& op);

    static void decryptInit(CipherCtx* ctx, const Cipher* cipher);

    static void decrypt(CipherCtx* ctx, CipherOperation& op);
};

} // namespace snet::tls