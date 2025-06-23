/// @file
/// @brief Declaration of the TLS session class.

#pragma once
#include <vector>
#include <array>
#include <span>
#include <memory>
#include <string>
#include <functional>
#include <unordered_map>

#include <snet/tls/alert.hpp>
#include <snet/tls/record_decoder.hpp>
#include <snet/tls/secret_node_manager.hpp>
#include <snet/tls/client_random.hpp>
#include <snet/tls/extensions.hpp>
#include <snet/tls/handshake_hash.hpp>
#include <snet/tls/record.hpp>
#include <snet/tls/server_info.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/record_pool.hpp>
#include <snet/tls/record_processor.hpp>
#include <snet/tls/handshake_msgs.hpp>

namespace snet::tls
{

/// @brief Class representing a TLS session.
class Session
{
public:
    /// @brief Default constructor.
    explicit Session(RecordPool& recordPool);

    void setProcessor(const RecordProcessor& processor)
    {
        processor_ = processor;
    }

    bool getCipherState(const std::int8_t sideIndex) const noexcept;

    bool canDecrypt(const std::int8_t sideIndex) const noexcept;

    size_t processRecords(const std::int8_t sideIndex, std::span<const std::uint8_t> input);

    void preprocessRecord(const std::int8_t sideIndex, Record* record);

    void postprocessRecord(const std::int8_t sideIndex, Record* record);

    /// @brief Decrypts a TLS record.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param record TLS record.
    ///
    void decrypt(const std::int8_t sideIndex, Record* record);

    /// @brief Checks if the session can decrypt data.
    /// @param client2server Indicates if the direction is client to server.
    /// @return True if the session can decrypt data, false otherwise.
    bool canDecrypt(bool client2server) const noexcept;

    /// @brief Generates key material using the PRF.
    /// @param secret The secret to use.
    /// @param usage The usage string.
    /// @param rnd1 The first random value.
    /// @param rnd2 The second random value.
    /// @param out The output buffer for the key material.
    void PRF(const Secret& secret, std::string_view usage, std::span<const uint8_t> rnd1, std::span<const uint8_t> rnd2,
             std::span<uint8_t> out);

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

    /// @brief Gets a secret of a specific type.
    /// @param type The type of the secret.
    /// @return The secret of the specified type.
    const Secret& getSecret(const SecretNode::Type type) const;

    /// @brief Sets the premaster secret for the session.
    /// @param pms The premaster secret to set.
    void setPremasterSecret(std::vector<std::uint8_t> pms);

    /// @brief Sets the server information for the session.
    /// @param serverInfo The server information to set.
    void setServerInfo(const ServerInfo& serverInfo);

    /// @brief Gets the server information of the session.
    /// @return The server information.
    const ServerInfo& getServerInfo() const noexcept;

    Record* readingRecord{nullptr};

    void processClientHello(const std::int8_t sideIndex, std::span<const uint8_t> message);

    void processServerHello(const std::int8_t sideIndex, std::span<const uint8_t> message);

    void processEncryptedExtensions(const std::int8_t sideIndex, std::span<const uint8_t> message);
    
    void processSessionTicket(const std::int8_t sideIndex, std::span<const uint8_t> message);

    void processCertificateRequest(const std::int8_t sideIndex, std::span<const uint8_t> message);

    void processCertificate(const std::int8_t sideIndex, std::span<const uint8_t> message);

    void processCertificateVerify(const std::int8_t sideIndex, std::span<const uint8_t> message);

    void processServerKeyExchange(const std::int8_t sideIndex, std::span<const uint8_t> message);

    void processClientKeyExchange(const std::int8_t sideIndex, std::span<const uint8_t> message);

    void processServerHelloDone(const std::int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Handles Finished message to create key material if it's necessary.
    /// @param sideIndex The side (client or server).
    void processFinished(const std::int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Handles KeyUpdate message to update key material if it's necessary.
    /// @param sideIndex The side (client or server).
    void processKeyUpdate(const std::int8_t sideIndex, std::span<const uint8_t> message);

private:
    HandshakeMessages handshake_;
    RecordPool& recordPool_;
    RecordProcessor processor_;
    ServerInfo serverInfo_;
    ProtocolVersion version_;
    CipherSuite cipherSuite_;
    std::vector<uint8_t> PMS_;
    SecretNode secrets_;
    RecordDecoder clientToServer_;
    RecordDecoder serverToClient_;
    HandshakeHash handshakeHash_;
    uint8_t cipherState_;
    uint8_t canDecrypt_;
    uint8_t debugKeys_;
};

} // namespace snet::tls