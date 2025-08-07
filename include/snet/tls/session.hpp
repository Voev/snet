/// @file
/// @brief Declaration of the TLS session class.

#pragma once
#include <vector>
#include <memory>
#include <string>
#include <cstddef>
#include <casket/nonstd/span.hpp>

#include <snet/tls/alert.hpp>
#include <snet/tls/secret_node_manager.hpp>
#include <snet/tls/client_random.hpp>
#include <snet/tls/extensions.hpp>
#include <snet/tls/handshake_hash.hpp>
#include <snet/tls/record.hpp>
#include <snet/tls/server_info.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/record_pool.hpp>
#include <snet/tls/record_layer.hpp>
#include <snet/tls/record_processor.hpp>
#include <snet/tls/handshake_msgs.hpp>
#include <snet/tls/cipher_suite.hpp>
#include <snet/tls/sequence_numbers.hpp>

namespace snet::tls
{

/// @brief Class representing a TLS session.
class Session
{
public:
    /// @brief Default constructor.
    explicit Session(RecordPool& recordPool);

    void reset() noexcept;

    void setProcessor(const RecordProcessor& processor)
    {
        processor_ = processor;
    }

    bool getCipherState(const int8_t sideIndex) const noexcept;

    size_t processRecords(const int8_t sideIndex, nonstd::span<const std::uint8_t> input);
    
    void preprocessRecord(const int8_t sideIndex, Record* record);

    void postprocessRecord(const int8_t sideIndex, Record* record);

    /// @brief Checks if the session can decrypt data.
    ///
    /// @param[in] client2server Indicates if the direction is client to server.
    ///
    /// @return true - if session can decrypt data, false - otherwise.
    bool canDecrypt(const int8_t sideIndex) const noexcept;

    /// @brief Decrypts a TLS record.
    ///
    /// @param[in] sideIndex The index indicating the side (client or server).
    /// @param[in] record TLS record.
    ///
    void decrypt(const int8_t sideIndex, Record* record);

    /// @brief Generates key material using the PRF.
    /// @param secret The secret to use.
    /// @param usage The usage string.
    /// @param rnd1 The first random value.
    /// @param rnd2 The second random value.
    /// @param out The output buffer for the key material.
    void PRF(const Secret& secret, std::string_view usage, nonstd::span<const uint8_t> rnd1, nonstd::span<const uint8_t> rnd2,
             nonstd::span<uint8_t> out);

    /// @brief Generates key material for the session.
    /// @param sideIndex The index indicating the side (client or server).
    void generateKeyMaterial(const int8_t sideIndex);

    /// @brief Generates key material for TLS 1.3.
    void generateTLS13KeyMaterial();

    /// @brief Gets the protocol version of the session.
    /// @return The protocol version.
    const ProtocolVersion& getVersion() const noexcept;

    /// @brief Gets the cipher suite of the session.
    /// @return The cipher suite.
    const CipherSuite& getCipherSuite() const noexcept;

    /// @brief Sets the secrets for the session.
    /// @param secrets The secrets to set.
    void setSecrets(SecretNode secrets);

    /// @brief Sets the premaster secret for the session.
    /// @param pms The premaster secret to set.
    void setPremasterSecret(std::vector<std::uint8_t> pms);

    /// @brief Sets the server information for the session.
    /// @param serverInfo The server information to set.
    void setServerInfo(const ServerInfo& serverInfo);

    /// @brief Gets the server information of the session.
    /// @return The server information.
    const ServerInfo& getServerInfo() const noexcept;

    void processClientHello(const ClientHello& clientHello);
    
    void processServerHello(const ServerHello& serverHello);
    
    void processEncryptedExtensions(const int8_t sideIndex, nonstd::span<const uint8_t> message);
    
    void processSessionTicket(const int8_t sideIndex, nonstd::span<const uint8_t> message);
    
    void processCertificateRequest(const int8_t sideIndex, nonstd::span<const uint8_t> message);
    
    void processCertificate(const int8_t sideIndex, nonstd::span<const uint8_t> message);
    
    void processCertificateVerify(const int8_t sideIndex, nonstd::span<const uint8_t> message);
    
    void processServerKeyExchange(const ServerKeyExchange& keyExchange);
    
    void processClientKeyExchange(const int8_t sideIndex, nonstd::span<const uint8_t> message);
    
    void processServerHelloDone(const int8_t sideIndex, nonstd::span<const uint8_t> message);
    
    /// @brief Handles Finished message to create key material if it's necessary.
    /// @param sideIndex The side (client or server).
    void processFinished(const int8_t sideIndex, const Finished& finished);
    
    /// @brief Handles KeyUpdate message to update key material if it's necessary.
    /// @param sideIndex The side (client or server).
    void processKeyUpdate(const int8_t sideIndex, nonstd::span<const uint8_t> message);
    
    void setDebugKeys(const bool debug)
    {
        debugKeys_ = debug;
    }

    /// @brief Fetch algorithms that are often used for operations on records.
    ///
    void fetchAlgorithms();

    std::string_view getHashAlgorithm() const;

private:
    RecordPool& recordPool_;
    RecordLayer recordLayer_;
    Record* readingRecord{nullptr};
    HandshakeMessages handshake_;
    crypto::HashCtxPtr hashCtx_;
    crypto::HashPtr hmacHashAlg_; ///< Fetched hash algorithm by cipher suite used in HMAC
    crypto::MacCtxPtr hmacCtx_; ///< HMAC context for TLSv1.2 (and earlier) non-AEAD cipher suites
    crypto::CipherPtr cipherAlg_; ///< Fetched cipher algorithm by cipher suite
    crypto::CipherCtxPtr clientCipherCtx_;
    crypto::CipherCtxPtr serverCipherCtx_;
    RecordProcessor processor_;
    ServerInfo serverInfo_;
    ProtocolVersion version_;
    const CipherSuite* cipherSuite_;
    std::array<uint8_t, TLS_RANDOM_SIZE> clientRandom_;
    std::array<uint8_t, TLS_RANDOM_SIZE> serverRandom_;
    SecretNode secrets_;
    std::vector<uint8_t> PMS_;
    std::vector<uint8_t> clientMacKey_;
    std::vector<uint8_t> serverMacKey_;
    std::vector<uint8_t> clientEncKey_;
    std::vector<uint8_t> serverEncKey_;
    std::vector<uint8_t> clientIV_;
    std::vector<uint8_t> serverIV_;
    HandshakeHash handshakeHash_;
    Extensions clientExtensions_;
    Extensions serverExtensions_;
    SequenceNumbers seqnum_;
    uint8_t cipherState_;
    uint8_t canDecrypt_;
    uint8_t debugKeys_;
};

} // namespace snet::tls