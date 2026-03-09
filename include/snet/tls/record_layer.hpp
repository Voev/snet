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

/// @brief Handles TLS record layer encryption and decryption.
///
/// The RecordLayer class manages the encryption and decryption of TLS records
/// for different protocol versions (TLS 1.0-1.3) and cipher modes (stream,
/// block, AEAD). It handles the cryptographic operations including MAC
/// calculation, padding, and sequence number management.
class RecordLayer final
{
public:
    /// @brief Reset the record layer to initial state.
    ///
    /// Clears all cryptographic parameters and resets to uninitialized state.
    void reset() noexcept
    {
        version_ = ProtocolVersion();
        tagLength_ = 0;
        encryptThenMAC_ = false;
        aead_ = false;
    }

    /// @brief Set the TLS protocol version.
    ///
    /// @param[in] version The protocol version to use.
    inline void setVersion(const ProtocolVersion& version) noexcept
    {
        version_ = version;
    }

    /// @brief Enable Encrypt-then-MAC mode.
    ///
    /// When enabled, encryption is performed before MAC calculation
    /// (as opposed to MAC-then-encrypt).
    inline void enableEncryptThenMAC() noexcept
    {
        encryptThenMAC_ = true;
    }

    /// @brief Set the authentication tag length.
    ///
    /// @param[in] tagLength Length of the authentication tag in bytes.
    inline void setTagLength(int tagLength) noexcept
    {
        tagLength_ = tagLength;
    }

    /// @brief Enable AEAD mode.
    ///
    /// Enables Authenticated Encryption with Associated Data mode.
    inline void enableAEAD() noexcept
    {
        aead_ = true;
    }

    /// @brief Initialize cipher context for TLS 1.2 and below.
    ///
    /// @param[in] ctx Cipher context to initialize.
    /// @param[in] cipher Cipher algorithm to use.
    /// @param[in] key Encryption/decryption key.
    /// @param[in] iv Initialization vector.
    /// @param[in] encrypt True for encryption, false for decryption.
    static void init(CipherCtx* ctx, const Cipher* cipher, nonstd::span<const uint8_t> key,
                     nonstd::span<const uint8_t> iv, bool encrypt);

    /// @brief Encrypt a TLS record.
    ///
    /// @param[in] cipherCtx Cipher context for encryption.
    /// @param[in] hmacCtx HMAC context for MAC calculation.
    /// @param[in] hashCtx Hash context for legacy MAC.
    /// @param[in] hmacHash Hash algorithm for HMAC.
    /// @param[in,out] record Record to encrypt.
    /// @param[in] seq Sequence number for MAC calculation.
    /// @param[in] macKey Key for MAC calculation.
    /// @param[in] iv Initialization vector.
    void encrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, Record* record,
                 uint64_t seq, nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv);

    /// @brief Decrypt a TLS record.
    ///
    /// @param[in] cipherCtx Cipher context for decryption.
    /// @param[in] hmacCtx HMAC context for MAC verification.
    /// @param[in] hashCtx Hash context for legacy MAC.
    /// @param[in] hmacHash Hash algorithm for HMAC.
    /// @param[in,out] record Record to decrypt.
    /// @param[in] seq Sequence number for MAC verification.
    /// @param[in] macKey Key for MAC verification.
    /// @param[in] iv Initialization vector.
    void decrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, Record* record,
                 uint64_t seq, nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv);

    /// @brief Initialize AEAD cipher for TLS 1.2.
    ///
    /// @param[in] ctx Cipher context to initialize.
    /// @param[in] cipher AEAD cipher algorithm to use.
    /// @param[in] key Encryption/decryption key.
    /// @param[in] iv Initialization vector.
    /// @param[in] encrypt True for encryption, false for decryption.
    void doTLSv1AeadInit(CipherCtx* ctx, const Cipher* cipher, nonstd::span<const uint8_t> key,
                         nonstd::span<const uint8_t> iv, bool encrypt);

    /// @brief Encrypt TLS 1.2 AEAD record.
    ///
    /// @param[in] cipherCtx Cipher context.
    /// @param[in] record Record to encrypt.
    /// @param[in] seq Sequence number.
    void doTLSv1AeadEncrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq);

    /// @brief Decrypt TLS 1.2 AEAD record.
    ///
    /// @param[in] cipherCtx Cipher context.
    /// @param[in] record Record to decrypt.
    /// @param[in] seq Sequence number.
    void doTLSv1AeadDecrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq);

    /// @brief Encrypt TLS 1.0/1.1/1.2 record with MAC-then-encrypt.
    ///
    /// @param[in] cipherCtx Cipher context for encryption.
    /// @param[in] hmacCtx HMAC context for MAC calculation.
    /// @param[in] hashCtx Hash context for legacy MAC.
    /// @param[in] hmacHash Hash algorithm for HMAC.
    /// @param[in,out] record Record to encrypt.
    /// @param[in] seq Sequence number for MAC calculation.
    /// @param[in] macKey Key for MAC calculation.
    void doTLSv1Encrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, Record* record,
                        uint64_t seq, nonstd::span<const uint8_t> macKey);

    /// @brief Decrypt TLS 1.0/1.1/1.2 record with MAC-then-encrypt.
    ///
    /// @param[in] cipherCtx Cipher context for decryption.
    /// @param[in] hmacCtx HMAC context for MAC verification.
    /// @param[in] hashCtx Hash context for legacy MAC.
    /// @param[in] hmacHash Hash algorithm for HMAC.
    /// @param[in,out] record Record to decrypt.
    /// @param[in] seq Sequence number for MAC verification.
    /// @param[in] macKey Key for MAC verification.
    void doTLSv1Decrypt(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash, Record* record,
                        uint64_t seq, nonstd::span<const uint8_t> macKey);

    /// @brief Initialize AEAD cipher for TLS 1.3.
    ///
    /// @param[in] ctx Cipher context to initialize.
    /// @param[in] cipher AEAD cipher algorithm to use.
    /// @param[in] key Encryption/decryption key.
    /// @param[in] encrypt True for encryption, false for decryption.
    void doTLSv13AeadInit(CipherCtx* ctx, const Cipher* cipher, nonstd::span<const uint8_t> key, bool encrypt);

    /// @brief Update traffic key for TLS 1.3.
    ///
    /// @param[in] ctx Cipher context to update.
    /// @param[in] key New traffic key.
    void doTLSv13KeyUpdate(CipherCtx* ctx, nonstd::span<const uint8_t> key);

    /// @brief Encrypt TLS 1.3 record.
    ///
    /// @param[in] cipherCtx Cipher context.
    /// @param[in,out] record Record to encrypt.
    /// @param[in] seq Sequence number.
    /// @param[in] iv Initialization vector.
    void doTLSv13Encrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq, nonstd::span<const uint8_t> iv);

    /// @brief Decrypt TLS 1.3 record.
    ///
    /// @param[in] cipherCtx Cipher context.
    /// @param[in,out] record Record to decrypt.
    /// @param[in] seq Sequence number.
    /// @param[in] iv Initialization vector.
    void doTLSv13Decrypt(CipherCtx* cipherCtx, Record* record, uint64_t seq, nonstd::span<const uint8_t> iv);

    /// @brief Prepare record for encryption.
    ///
    /// Adjusts data offset based on TLS header and cipher requirements.
    ///
    /// @param[in] record Record to prepare.
    /// @param[in] cipher Cipher algorithm to determine offset.
    void prepareRecordForEncrypt(Record* record, const Cipher* cipher)
    {
        int prefixLength = 0;
        if (aead_ && version_ <= ProtocolVersion::TLSv1_3)
        {
            prefixLength += crypto::CipherTraits::getExplicitNonceLength(cipher);
        }
        record->setDataOffset(prefixLength);
    }

private:
    /// @brief Verify TLS 1.0/1.1/1.2 MAC.
    ///
    /// @param[in] hmacCtx HMAC context.
    /// @param[in] hmacHash Hash algorithm for HMAC.
    /// @param[in] recordType Type of record.
    /// @param[in] seq Sequence number.
    /// @param[in] macKey MAC key.
    /// @param[in] iv Initialization vector.
    /// @param[in] content Record content.
    /// @param[in] mac Received MAC to verify.
    void tls1CheckMac(MacCtx* hmacCtx, const Hash* hmacHash, RecordType recordType, uint64_t seq,
                      nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> iv,
                      nonstd::span<const uint8_t> content, nonstd::span<const uint8_t> mac);

    /// @brief Verify SSL 3.0 MAC.
    ///
    /// @param[in] ctx Hash context.
    /// @param[in] hmacHash Hash algorithm.
    /// @param[in] recordType Type of record.
    /// @param[in] seq Sequence number.
    /// @param[in] macKey MAC key.
    /// @param[in] content Record content.
    /// @param[in] mac Received MAC to verify.
    void ssl3CheckMac(HashCtx* ctx, const Hash* hmacHash, RecordType recordType, uint64_t seq,
                      nonstd::span<const uint8_t> macKey, nonstd::span<const uint8_t> content,
                      nonstd::span<const uint8_t> mac);

    /// @brief Process TLS 1.0/1.1/1.2 data with MAC-then-encrypt.
    ///
    /// @param[in] cipherCtx Cipher context.
    /// @param[in] hmacCtx HMAC context.
    /// @param[in] hashCtx Hash context.
    /// @param[in] hmacHash Hash algorithm.
    /// @param[in] rt Record type.
    /// @param[in] seq Sequence number.
    /// @param[in] macKey MAC key.
    /// @param[in] in Input buffer.
    /// @param[out] out Output buffer.
    ///
    /// @return Processed data span.
    nonstd::span<uint8_t> doTLSv1Process(CipherCtx* cipherCtx, MacCtx* hmacCtx, HashCtx* hashCtx, const Hash* hmacHash,
                                         RecordType rt, uint64_t seq, nonstd::span<const uint8_t> macKey,
                                         nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out);

    /// @brief Process TLS 1.2 AEAD data.
    ///
    /// @param[in] cipherCtx Cipher context.
    /// @param[in] rt Record type.
    /// @param[in] seq Sequence number.
    /// @param[in] in Input/output data buffer.
    /// @param[in] encrypt True for encryption, false for decryption.
    ///
    /// @return Processed data span.
    nonstd::span<uint8_t> doTLSv1AeadProcess(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                             nonstd::span<uint8_t> in, bool encrypt);

    /// @brief Process TLS 1.3 data.
    ///
    /// @param[in] cipherCtx Cipher context.
    /// @param[in] rt Record type.
    /// @param[in] seq Sequence number.
    /// @param[in] iv Initialization vector.
    /// @param[in] in Input buffer.
    /// @param[out] out Output buffer.
    /// @param[in] encrypt True for encryption, false for decryption.
    ///
    /// @return Processed data span.
    nonstd::span<std::uint8_t> doTLSv13Process(CipherCtx* cipherCtx, RecordType rt, uint64_t seq,
                                               nonstd::span<const uint8_t> iv, nonstd::span<const uint8_t> in,
                                               nonstd::span<uint8_t> out, bool encrypt);

private:
    ProtocolVersion version_;    ///< TLS protocol version.
    int tagLength_{0};           ///< Authentication tag length in bytes.
    bool encryptThenMAC_{false}; ///< True if Encrypt-then-MAC is enabled.
    bool aead_{false};           ///< True if using AEAD cipher mode.
};

} // namespace snet::tls