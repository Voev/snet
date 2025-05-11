#pragma once
#include <span>
#include <vector>

#include <snet/crypto/typedefs.hpp>
#include <snet/tls/record/cipher_traits.hpp>

namespace snet::tls::v1
{

class BlockCipher
{
public:
    static void initDecrypt(CipherCtx* ctx, const CipherTraits& traits,
                            std::span<const uint8_t> encKey, std::span<const uint8_t> encIV);

    static void decrypt(CipherCtx* cipherCtx, const CipherTraits& traits,
                        uint64_t seq, RecordType rt, std::span<const uint8_t> in,
                        std::vector<uint8_t>& out, std::span<const uint8_t> macKey);
};
} // namespace snet::tls::v1