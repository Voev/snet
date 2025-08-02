/// @file
/// @brief Declaration of the RecordDecoder class.

#pragma once
#include <vector>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

class RecordLayer final
{
public:
    static void init(CipherCtx* ctx, const Cipher* cipher);

    static void init(CipherCtx* ctx, const Cipher* cipher, nonstd::span<const uint8_t> key,
                     nonstd::span<const uint8_t> iv);

    static nonstd::span<std::uint8_t> tls1Decrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx,
                                                  const Hash* hmacHash, RecordType rt, ProtocolVersion version,
                                                  uint64_t seq, nonstd::span<const uint8_t> key,
                                                  nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv,
                                                  nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out,
                                                  int tagLength, bool encryptThenMac, bool aead);

    static nonstd::span<std::uint8_t> tls13Encrypt(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                                   nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv,
                                                   nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out,
                                                   int tagLength);

    static nonstd::span<std::uint8_t> tls13Decrypt(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                                   nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv,
                                                   nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out,
                                                   int tagLength);

private:
    static void tls1CheckMac(MacCtx* hmacCtx, RecordType recordType, ProtocolVersion version, uint64_t seq,
                             nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv,
                             nonstd::span<const uint8_t> content, nonstd::span<const uint8_t> mac);

    static void ssl3CheckMac(HashCtx* ctx, const Hash* hmacHash, RecordType recordType, uint64_t seq,
                             nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> content,
                             nonstd::span<const uint8_t> mac);

    static nonstd::span<std::uint8_t> tls13process(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                                   nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv,
                                                   nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out,
                                                   int tagLength, bool encrypt);
};

} // namespace snet::tls
