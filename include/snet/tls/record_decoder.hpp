/// @file
/// @brief Declaration of the RecordDecoder class.

#pragma once
#include <vector>
#include <span>
#include <snet/tls/types.hpp>
#include <snet/tls/cipher_suite.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

/// @brief Class for decoding TLS records.
class RecordDecoder final
{
public:
    /// @brief Default constructor.
    RecordDecoder();

    /// @brief Destructor.
    ~RecordDecoder() noexcept;

    bool isInited() const noexcept;

    void reset() noexcept;

    /// @brief Initializes the encryption context and MAC computation.
    /// @param cs The cipher suite.
    /// @param encKey The encryption key.
    /// @param encIV The encryption IV.
    /// @param macKey The MAC key.
    void init(CipherSuite cs, std::span<const uint8_t> encKey, std::span<const uint8_t> encIV,
              std::span<const std::uint8_t> macKey);

    /// @brief Initializes AEAD mode.
    /// @param cs The cipher suite.
    /// @param encKey The encryption key.
    /// @param encIV The encryption IV.
    void init(CipherSuite cs, std::span<const uint8_t> encKey, std::span<const uint8_t> encIV);

    /// @brief Decrypts a TLS 1.x record.
    /// @param rt The record type.
    /// @param version The protocol version.
    /// @param in The input data.
    /// @param out The output buffer for the decrypted data.
    /// @param encryptThenMac Indicates if Encrypt-then-MAC is used.
    void tls1Decrypt(RecordType rt, ProtocolVersion version, std::span<const uint8_t> in,
                     std::vector<uint8_t>& out, bool encryptThenMac);

    /// @brief Decrypts a TLS 1.3 record.
    /// @param rt The record type.
    /// @param in The input data.
    /// @param out The output buffer for the decrypted data.
    void tls13Decrypt(RecordType rt, std::span<const uint8_t> in, std::vector<uint8_t>& out);

    /// @brief Updates the keys for TLS 1.3.
    /// @param newkey The new encryption key.
    /// @param newiv The new initialization vector.
    void tls13UpdateKeys(const std::vector<uint8_t>& newkey, const std::vector<uint8_t>& newiv);

private:
    /// @brief Checks the MAC for SSL 3.0.
    /// @param recordType The record type.
    /// @param content The content data.
    /// @param mac The MAC to check.
    void ssl3CheckMac(RecordType recordType, std::span<const uint8_t> content,
                      std::span<const uint8_t> mac);

    /// @brief Checks the MAC for TLS 1.x.
    /// @param recordType The record type.
    /// @param version The protocol version.
    /// @param iv The initialization vector.
    /// @param content The content data.
    /// @param mac The MAC to check.
    void tls1CheckMac(RecordType recordType, ProtocolVersion version, std::span<const uint8_t> iv,
                      std::span<const uint8_t> content, std::span<const uint8_t> mac);

private:
    CipherSuite cipherSuite_;
    std::vector<uint8_t> macKey_;
    std::vector<uint8_t> implicitIv_; /* for AEAD ciphers */
    std::vector<uint8_t> writeKey_;   /* for AEAD ciphers */
    EvpCipherCtxPtr cipher_;
    uint64_t seq_;
    bool inited_;
};

} // namespace snet::tls
