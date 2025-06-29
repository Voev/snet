/// @file
/// @brief Declaration of the RecordDecoder class.

#pragma once
#include <vector>
#include <casket/nonstd/span.hpp>
#include <snet/crypto/pointers.hpp>
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
    void init(CipherSuite cs, nonstd::span<const uint8_t> encKey, nonstd::span<const uint8_t> encIV,
              nonstd::span<const std::uint8_t> macKey);

    /// @brief Initializes AEAD mode.
    /// @param cs The cipher suite.
    /// @param encKey The encryption key.
    /// @param encIV The encryption IV.
    void init(CipherSuite cs, nonstd::span<const uint8_t> encKey, nonstd::span<const uint8_t> encIV);

    /// @brief Updates the keys for TLS 1.3.
    /// @param newkey The new encryption key.
    /// @param newiv The new initialization vector.
    void tls13UpdateKeys(const std::vector<uint8_t>& newkey, const std::vector<uint8_t>& newiv);

    /// @brief Decrypts a TLS 1.x record.
    /// @param rt The record type.
    /// @param version The protocol version.
    /// @param in The input data.
    /// @param out The output buffer for the decrypted data.
    /// @param encryptThenMac Indicates if Encrypt-then-MAC is used.
    nonstd::span<std::uint8_t> tls1Decrypt(RecordType rt, ProtocolVersion version, nonstd::span<const uint8_t> in,
                                        nonstd::span<uint8_t> out, bool encryptThenMac);

    /// @brief Decrypts a TLS 1.3 record.
    /// @param rt The record type.
    /// @param in The input data.
    /// @param out The output buffer for the decrypted data.
    nonstd::span<std::uint8_t> tls13Decrypt(RecordType rt, nonstd::span<const uint8_t> in, nonstd::span<uint8_t> out);

private:
    /// @brief Checks the MAC for SSL 3.0.
    /// @param recordType The record type.
    /// @param content The content data.
    /// @param mac The MAC to check.
    void ssl3CheckMac(RecordType recordType, nonstd::span<const uint8_t> content, nonstd::span<const uint8_t> mac);

    /// @brief Checks the MAC for TLS 1.x.
    /// @param recordType The record type.
    /// @param version The protocol version.
    /// @param iv The initialization vector.
    /// @param content The content data.
    /// @param mac The MAC to check.
    void tls1CheckMac(RecordType recordType, ProtocolVersion version, nonstd::span<const uint8_t> iv,
                      nonstd::span<const uint8_t> content, nonstd::span<const uint8_t> mac);

private:
    CipherSuite cipherSuite_;
    std::vector<uint8_t> macKey_;     /* for NON-AEAD ciphers */
    std::vector<uint8_t> implicitIv_; /* for AEAD ciphers */
    crypto::CipherCtxPtr cipher_;
    std::uint64_t seq_;
    bool inited_;
};

} // namespace snet::tls
