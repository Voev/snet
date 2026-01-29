/// @file
/// @brief Declaration of the RecordDecoder class.

#pragma once
#include <vector>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/pointers.hpp>
#include <snet/crypto/cipher_traits.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/version.hpp>
#include <snet/tls/record.hpp>

namespace snet::tls
{

class RecordLayer final
{
public:
    struct Operation
    {
        CipherCtx* cipherCtx;
        MacCtx* hmacCtx;
        HashCtx* hashCtx;
        const Hash* hmacHash;

        uint8_t* encKey;
        uint8_t* macKey;
        uint8_t* iv;
    };

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

    static void init(CipherCtx* ctx, const Cipher* cipher, nonstd::span<const uint8_t> key,
                     nonstd::span<const uint8_t> iv);

    void decrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, Record* record,
                 uint64_t seq, nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> macKey,
                 nonstd::span<const uint8_t> iv);

    void doTLSv1AeadEncrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq, nonstd::span<const uint8_t> key,
                            nonstd::span<const uint8_t> iv);

    void doTLSv1AeadDecrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq, nonstd::span<const uint8_t> key,
                            nonstd::span<const uint8_t> iv);

    nonstd::span<uint8_t> doTLSv1AeadProcess(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                             nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv,
                                             nonstd::span<uint8_t> in, bool encrypt);

    void doTLSv1Encrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, Record* record,
                        uint64_t seq, nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> macKey,
                        nonstd::span<const uint8_t> iv);

    void doTLSv1Decrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, Record* record,
                        uint64_t seq, nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> macKey,
                        nonstd::span<const uint8_t> iv);

    void doTLSv13Encrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq, nonstd::span<const uint8_t> key,
                         nonstd::span<const uint8_t> iv);

    void doTLSv13Decrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq, nonstd::span<const uint8_t> key,
                         nonstd::span<const uint8_t> iv);

    void prepareRecordForEncrypt(Record* record, const Cipher* cipher)
    {
        if( aead_ && version_ <= ProtocolVersion::TLSv1_3 )
        {
            auto prefixLength = crypto::CipherTraits::getExplicitNonceLength(cipher);
            record->setDataOffset( prefixLength );
        }
    }

private:
    void tls1CheckMac(MacCtx* hmacCtx, const Hash* hmacHash, RecordType recordType, uint64_t seq,
                      nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv,
                      nonstd::span<const uint8_t> content, nonstd::span<const uint8_t> mac);

    void ssl3CheckMac(HashCtx* ctx, const Hash* hmacHash, RecordType recordType, uint64_t seq,
                      nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> content,
                      nonstd::span<const uint8_t> mac);

    nonstd::span<uint8_t> doTLSv1Process(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash,
                                         RecordType rt, uint64_t seq, nonstd::span<const uint8_t> key,
                                         nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv,
                                         nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out, bool encrypt);

    nonstd::span<std::uint8_t> doTLSv13Process(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                               nonstd::span<const uint8_t> key, nonstd::span<const uint8_t> iv,
                                               nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out, bool encrypt);



private:
    ProtocolVersion version_;
    int tagLength_{0};
    bool encryptThenMAC_{false};
    bool aead_{false};
};

} // namespace snet::tls
