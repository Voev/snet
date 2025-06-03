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

namespace snet::tls
{

/// @brief Class representing a TLS session.
class Session
{
public:
    /// @brief Default constructor.
    Session();

    /// @brief Decrypts a TLS record.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param recordType The type of the record.
    /// @param recordVersion The version of the record.
    /// @param inputBytes The input bytes to decrypt.
    /// @param outputBytes The output buffer for the decrypted data.
    void decrypt(const std::int8_t sideIndex, RecordType recordType, ProtocolVersion recordVersion,
                 std::span<const uint8_t> inputBytes, std::vector<std::uint8_t>& outputBytes);

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
    void PRF(const Secret& secret, std::string_view usage, std::span<const uint8_t> rnd1,
             std::span<const uint8_t> rnd2, std::span<uint8_t> out);

    /// @brief Generates key material for the session.
    /// @param sideIndex The index indicating the side (client or server).
    void generateKeyMaterial(const int8_t sideIndex);

    /// @brief Generates key material for TLS 1.3.
    void generateTLS13KeyMaterial();

    /// @brief Handles Finished message to create key material if it's necessary.
    /// @param sideIndex The side (client or server).
    void processFinished(const std::int8_t sideIndex);

    /// @brief Handles KeyUpdate message to update key material if it's necessary.
    /// @param sideIndex The side (client or server).
    void processKeyUpdate(const std::int8_t sideIndex);

    /// @brief Deserializes extensions from a data reader.
    /// @param reader The data reader.
    /// @param side The side (client or server).
    /// @param ht The handshake type.
    void deserializeExtensions(const Side side, std::span<const uint8_t> input);

    /// @brief Gets the extensions for a specific side.
    /// @param side The side (client or server).
    /// @return The extensions for the specified side.
    const Extensions& getExtensions(const Side side) const noexcept;

    /// @brief Updates the handshake hash with a message.
    /// @param message The message to update the hash with.
    void updateHash(std::span<const uint8_t> message);

    /// @brief Sets the client random value.
    /// @param random The client random value to set.
    void setClientRandom(ClientRandom random);

    /// @brief Gets the client random value.
    /// @return The client random value.
    const ClientRandom& getClientRandom() const noexcept;

    /// @brief Sets the server random value.
    /// @param random The server random value to set.
    void setServerRandom(ServerRandom random);

    /// @brief Sets the session ID.
    /// @param sessionID The session ID to set.
    void setSessionID(std::vector<std::uint8_t> sessionID);

    /// @brief Sets the protocol version.
    /// @param version The protocol version to set.
    void setVersion(ProtocolVersion version);

    /// @brief Gets the protocol version of the session.
    /// @return The protocol version.
    const ProtocolVersion& getVersion() const noexcept;

    /// @brief Sets the cipher suite for the session.
    /// @param cipherSuite The cipher suite to set.
    void setCipherSuite(const CipherSuite& cipherSuite);

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

    /// @brief Sets the cipher state.
    /// @param state The cipher state to set.
    void cipherState(bool state) noexcept;

    /// @brief Gets the cipher state.
    /// @return The cipher state.
    bool cipherState() const noexcept;

private:
    ServerInfo serverInfo_;
    ProtocolVersion version_;
    CipherSuite cipherSuite_;
    std::vector<uint8_t> PMS_;
    ClientRandom clientRandom_;
    ServerRandom serverRandom_;
    SecretNode secrets_;
    std::vector<uint8_t> sessionId_;
    RecordDecoder clientToServer_;
    RecordDecoder serverToClient_;
    Extensions clientExtensions_;
    Extensions serverExtensions_;
    HandshakeHash handshakeHash_;
    bool cipherState_;
};

} // namespace snet::tls