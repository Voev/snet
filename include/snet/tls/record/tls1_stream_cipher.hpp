#pragma once
#include <span>

#include <snet/crypto/typedefs.hpp>
#include <snet/tls/record/cipher_traits.hpp>

namespace snet::tls::v1
{

class StreamCipher
{
public:
    static void initDecrypt(CipherCtx* ctx, const CipherTraits& traits,
                            std::span<const uint8_t> encKey, std::span<const uint8_t> encIV);

    static void decrypt(CipherCtx* cipherCtx, const CipherTraits& traits,
                        Record& record, std::span<const uint8_t> macKey);
};

} // namespace snet::tls::v1