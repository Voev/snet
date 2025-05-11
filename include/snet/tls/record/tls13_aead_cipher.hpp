#pragma once
#include <span>
#include <vector>

#include <snet/crypto/typedefs.hpp>
#include <snet/tls/record/cipher_traits.hpp>

namespace snet::tls::v13
{

class AeadCipher
{
public:
    static void initDecrypt(CipherCtx* ctx, const CipherTraits& traits,
                            std::span<const uint8_t> encKey);

    static void decrypt(CipherCtx* cipherCtx, const CipherTraits& traits, uint64_t seq,
                        RecordType rt, std::span<const uint8_t> in, std::vector<uint8_t>& out,
                        std::span<const uint8_t> implicitIV);
};

} // namespace snet::tls::v13