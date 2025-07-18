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

class RecordDecoder final
{
public:
    RecordDecoder();

    ~RecordDecoder() noexcept;

    bool isInited() const noexcept;

    void reset() noexcept;

    void init(const Cipher* cipher, nonstd::span<const uint8_t> encKey, nonstd::span<const uint8_t> encIV,
              nonstd::span<const std::uint8_t> macKey);

    void init(const Cipher* cipher, nonstd::span<const uint8_t> encKey, nonstd::span<const uint8_t> encIV);

    void tls13UpdateKeys(const std::vector<uint8_t>& newkey, const std::vector<uint8_t>& newiv);

    nonstd::span<std::uint8_t> tls1Decrypt(MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, RecordType rt,
                                           ProtocolVersion version, nonstd::span<const uint8_t> in,
                                           nonstd::span<uint8_t> out, int tagLength, bool encryptThenMac, bool aead);

    nonstd::span<std::uint8_t> tls13Decrypt(RecordType rt, nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out,
                                            int tagLength);

private:
    void tls1CheckMac(MacCtx* hmacCtx, RecordType recordType, ProtocolVersion version, nonstd::span<const uint8_t> iv,
                      nonstd::span<const uint8_t> content, nonstd::span<const uint8_t> mac);

    void ssl3CheckMac(HashCtx* ctx, const Hash* hmacHash, RecordType recordType, nonstd::span<const uint8_t> content,
                      nonstd::span<const uint8_t> mac);

private:
    std::vector<uint8_t> macKey_; /* for NON-AEAD ciphers */
    std::vector<uint8_t> iv_;     /* for AEAD ciphers */
    std::vector<uint8_t> key_;
    crypto::CipherCtxPtr cipher_;
    std::uint64_t seq_;
    bool inited_;
};

} // namespace snet::tls
