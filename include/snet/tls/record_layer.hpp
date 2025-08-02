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
    void reset() noexcept
    {
        version_ = ProtocolVersion();
        tagLength_ = 0;
        encryptThenMAC_ = false;
        aead_ = false;
    }

    inline void setVersion(const ProtocolVersion& version) noexcept
    {
        version_ = version;
    }

    inline void enableEncryptThenMAC() noexcept
    {
        encryptThenMAC_ = true;
    }

    inline void setTagLength(int tagLength) noexcept
    {
        tagLength_ = tagLength;
    }

    inline void enableAEAD() noexcept
    {
        aead_ = true;
    }

    static void init(CipherCtx* ctx, const Cipher* cipher);

    static void init(CipherCtx* ctx, const Cipher* cipher, nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv);

    nonstd::span<std::uint8_t> tls1Decrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx,
                                           const Hash* hmacHash, RecordType rt, uint64_t seq,
                                           nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> macKey,
                                           nonstd::span<const uint8_t> iv, nonstd::span<const uint8_t> in,
                                           nonstd::span<uint8_t> out);

    nonstd::span<std::uint8_t> tls13Encrypt(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                            nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv,
                                            nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out);

    nonstd::span<std::uint8_t> tls13Decrypt(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                            nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv,
                                            nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out);

private:
    void tls1CheckMac(MacCtx* hmacCtx, RecordType recordType, ProtocolVersion version, uint64_t seq,
                      nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv,
                      nonstd::span<const uint8_t> content, nonstd::span<const uint8_t> mac);

    void ssl3CheckMac(HashCtx* ctx, const Hash* hmacHash, RecordType recordType, uint64_t seq,
                      nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> content,
                      nonstd::span<const uint8_t> mac);

    nonstd::span<std::uint8_t> tls13process(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                            nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv,
                                            nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out,
                                            bool encrypt);

private:
    ProtocolVersion version_;
    int tagLength_{0};
    bool encryptThenMAC_{false};
    bool aead_{false};
};

} // namespace snet::tls
