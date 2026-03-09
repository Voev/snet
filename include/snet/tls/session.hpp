/// @file
/// @brief Declaration of the TLS session class.

#pragma once
#include <vector>
#include <memory>
#include <string>
#include <cstddef>

#include <casket/types/ring_buffer.hpp>

#include <snet/crypto/secure_array.hpp>
#include <snet/crypto/signature_scheme.hpp>
#include <snet/crypto/group_params.hpp>

#include <snet/tls/alert.hpp>
#include <snet/tls/secret_node_manager.hpp>
#include <snet/tls/client_random.hpp>
#include <snet/tls/extensions.hpp>
#include <snet/tls/record.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/record_pool.hpp>
#include <snet/tls/record_layer.hpp>
#include <snet/tls/cipher_suite.hpp>
#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/tls/sequence_numbers.hpp>

namespace snet::tls
{

/// @brief Class representing a TLS session.
///
/// Manages the state of a TLS connection including cryptographic parameters,
/// record processing, handshake state machine, and key scheduling. Handles
/// both TLS 1.2 and TLS 1.3 protocols.
class Session
{
public:
    /// @brief Default constructor.
    ///
    /// @param[in] recordPool Reference to record pool for memory management.
    explicit Session(RecordPool& recordPool);

    /// @brief Reset the session to initial state.
    void reset() noexcept;

    /// @brief Check if cipher state is available for a side.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    ///
    /// @return True if cipher state is available, false otherwise.
    bool getCipherState(const int8_t sideIndex) const noexcept;

    /// @brief Read and parse records from input buffer.
    ///
    /// @param[in] input Raw bytes containing TLS records.
    ///
    /// @return Number of bytes consumed from input.
    size_t readRecords(nonstd::span<const uint8_t> input);

    /// @brief Write records to output buffer.
    ///
    /// @param[in] output Buffer to write serialized records to.
    ///
    /// @return Number of bytes written to output.
    size_t writeRecords(nonstd::span<uint8_t> output);

    /// @brief Process records for a specific side.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] input Raw bytes containing records to process.
    ///
    /// @return Number of bytes processed.
    size_t processRecords(const int8_t sideIndex, nonstd::span<const std::uint8_t> input);

    /// @brief Processes all pending records in the queue with a custom handler.
    ///
    /// @tparam Handler A callable type that handles individual records.
    /// @param[in] sideIndex Indicates which side's records to process (0 for client, 1 for server).
    /// @param[in] recordHandler Callback function or functor that processes each record
    ///                      Signature: void(const int8_t, Record*).
    ///
    /// @throws std::exception Propagates any exception from preprocessing, handling,
    ///                         postprocessing, or key scheduling.
    template <class Handler>
    void processPendingRecords(const int8_t sideIndex, Handler&& recordHandler)
    {
        while (!pendingRecords_.empty())
        {
            Record* record{nullptr};

            if (!pendingRecords_.pop(record))
            {
                continue;
            }

            try
            {
                preprocessRecord(sideIndex, record);

                recordHandler(sideIndex, record);

                postprocessRecord(sideIndex, record);

                keySchedule(sideIndex, false, record);
            }
            catch (const std::exception& e)
            {
                recordPool_.release(record);
                throw;
            }

            recordPool_.release(record);
        }
    }

    /// @brief Adds a record to the outgoing queue for transmission.
    ///
    /// @param[in] sideIndex Indicates which side is sending the record (0 for client, 1 for server).
    /// @param[in] record Pointer to the record to be added (takes ownership).
    ///
    /// @return True if record was successfully added, false otherwise.
    bool addOutgoingRecord(const int8_t sideIndex, Record* record)
    {
        if (record)
        {
            postprocessRecord(sideIndex, record);

            if (record->mustBeEncrypted())
            {
                encrypt(sideIndex, record);
            }

            keySchedule(sideIndex, true, record);

            return outgoingRecords_.push(record);
        }
        return false;
    }

    /// @brief Checks if the session can decrypt data.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    ///
    /// @return True if session can decrypt data, false otherwise.
    bool canDecrypt(const int8_t sideIndex) const noexcept;

    /// @brief Encrypt a TLS record.
    ///
    /// @param[in] sideIndex Index indicating the side (client or server).
    /// @param[in] record TLS record to encrypt.
    void encrypt(const int8_t sideIndex, Record* record);

    /// @brief Decrypt a TLS record.
    ///
    /// @param[in] sideIndex Index indicating the side (client or server).
    /// @param[in] record TLS record to decrypt.
    void decrypt(const int8_t sideIndex, Record* record);

    /// @brief Generates key material using the PRF.
    ///
    /// @param[in] secret The secret to use.
    /// @param[in] usage The usage string.
    /// @param[in] rnd1 The first random value.
    /// @param[in] rnd2 The second random value.
    /// @param[out] out The output buffer for the key material.
    void PRF(nonstd::span<const uint8_t> secret, std::string_view usage, nonstd::span<const uint8_t> rnd1,
             nonstd::span<const uint8_t> rnd2, nonstd::span<uint8_t> out);

    /// @brief Generates the handshake secret using ECDHE key exchange.
    ///
    /// @param[in] publicKey The peer's public key for key agreement.
    /// @param[in] privateKey The local private key for key agreement.
    void generateHandshakeSecret(Key* publicKey, Key* privateKey);

    /// @brief Generates the master secret for TLS 1.2 and below.
    void generateMasterSecret();

    /// @brief Generates the TLS 1.3 master secret from the handshake secret.
    ///
    /// @details Derives the master secret using HKDF-Extract and HKDF-Expand
    ///          operations as specified in RFC 8446.
    void generateTLSv13MasterSecret();

    /// @brief Derives the handshake traffic secrets for encrypting handshake messages.
    ///
    /// @details Generates the client_handshake_traffic_secret and
    ///          server_handshake_traffic_secret used for encrypting handshake records.
    void generateHandshakeTrafficSecrets();

    /// @brief Derives the application traffic secrets for encrypting application data.
    ///
    /// @details Generates the client_application_traffic_secret_0 and
    ///          server_application_traffic_secret_0 used for encrypting
    ///          application data records.
    void generateApplicationTrafficSecrets();

    /// @brief Generates key material for the session.
    ///
    /// @param[in] sideIndex Index indicating the side (client or server).
    /// @param[in] encrypt True for encryption keys, false for decryption keys.
    void generateKeyMaterial(const int8_t sideIndex, bool encrypt);

    /// @brief Generates the handshake keys and initialization vectors.
    ///
    /// @param[in] encrypt True for encryption keys, false for decryption keys.
    void generateHandshakeKeyAndIv(bool encrypt);

    /// @brief Generates the application data keys and initialization vectors.
    ///
    /// @param[in] sideIndex Indicates which side's keys to generate (0 for client, 1 for server).
    /// @param[in] encrypt True for encryption keys, false for decryption keys.
    void generateApplicationKeyAndIv(const int8_t sideIndex, bool encrypt);

    /// @brief Gets the protocol version of the session.
    ///
    /// @return The protocol version.
    const ProtocolVersion& getVersion() const noexcept;

    /// @brief Gets the protocol version to use for record layer.
    ///
    /// @return The record layer protocol version (TLS 1.2 for TLS 1.3 sessions).
    ProtocolVersion getRecordVersion() const noexcept
    {
        auto version = getVersion();
        if (version == ProtocolVersion::TLSv1_3)
        {
            version = ProtocolVersion::TLSv1_2;
        }
        return version;
    }

    /// @brief Sets the secrets for the session.
    ///
    /// @param[in] secrets The secrets to set.
    void setSecrets(const SecretNode* secrets);

    /// @brief Sets the premaster secret for the session.
    ///
    /// @param[in] pms The premaster secret to set.
    void setPremasterSecret(std::vector<std::uint8_t> pms);

    /// @brief Sets the server private key for the session.
    ///
    /// @param[in] key Server private key.
    void setServerKey(Key* key);

    /// @brief Process a Client Hello message.
    ///
    /// @tparam ExtensionsHandler Type of handler for extensions.
    /// @param[in] clientHello The Client Hello message.
    /// @param[in] handler Callback for processing extensions.
    template <typename ExtensionsHandler = std::nullptr_t>
    void processClientHello(const ClientHello& clientHello, ExtensionsHandler&& handler = nullptr);

    /// @brief Process a Server Hello message.
    ///
    /// @tparam ExtensionsHandler Type of handler for extensions.
    /// @param[in] serverHello The Server Hello message.
    /// @param[in] handler Callback for processing extensions.
    template <typename ExtensionsHandler = std::nullptr_t>
    void processServerHello(const ServerHello& serverHello, ExtensionsHandler&& handler = nullptr);

    /// @brief Process an Encrypted Extensions message.
    ///
    /// @param[in] encryptedExtensions The Encrypted Extensions message.
    void processEncryptedExtensions(const EncryptedExtensions& encryptedExtensions);

    /// @brief Process a New Session Ticket message.
    ///
    /// @param[in] sessionTicket The New Session Ticket message.
    void processNewSessionTicket(const NewSessionTicket& sessionTicket);

    /// @brief Process a Certificate message.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] certificate The Certificate message.
    void processCertificate(const int8_t sideIndex, const Certificate& certificate);

    /// @brief Process a Certificate Request message.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] certRequest The Certificate Request message.
    void processCertificateRequest(const int8_t sideIndex, const CertificateRequest& certRequest);

    /// @brief Process a Certificate Verify message.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] certVerify The Certificate Verify message.
    void processCertificateVerify(const int8_t sideIndex, const CertificateVerify& certVerify);

    /// @brief Process a Server Key Exchange message.
    ///
    /// @param[in] keyExchange The Server Key Exchange message.
    void processServerKeyExchange(const ServerKeyExchange& keyExchange);

    /// @brief Process a Client Key Exchange message.
    ///
    /// @param[in] keyExchange The Client Key Exchange message.
    void processClientKeyExchange(const ClientKeyExchange& keyExchange);

    /// @brief Handles Finished message to create key material if necessary.
    ///
    /// @param[in] sideIndex Side index (client or server).
    /// @param[in] finished The Finished message.
    void processFinished(const int8_t sideIndex, const Finished& finished);

    /// @brief Handles KeyUpdate message to update key material if necessary.
    ///
    /// @param[in] sideIndex Side index (client or server).
    /// @param[in] message The KeyUpdate message.
    void processKeyUpdate(const int8_t sideIndex, nonstd::span<const uint8_t> message);

    /// @brief Construct a Client Hello message.
    ///
    /// @param[out] clientHello The Client Hello message to construct.
    void constructClientHello(ClientHello& clientHello);

    /// @brief Construct a Certificate message.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] record Record to store the constructed message.
    void constructCertificate(const int8_t sideIndex, Record* record);

    /// @brief Construct a Certificate Verify message.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] record Record to store the constructed message.
    void constructCertificateVerify(const int8_t sideIndex, Record* record);

    /// @brief Construct a Server Key Exchange message.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] record Record to store the constructed message.
    void constructServerKeyExchange(const int8_t sideIndex, Record* record);

    /// @brief Construct a Client Key Exchange message.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] record Record to store the constructed message.
    void constructClientKeyExchange(const int8_t sideIndex, Record* record);

    /// @brief Construct a Server Hello Done message.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] record Record to store the constructed message.
    void constructServerHelloDone(const int8_t sideIndex, Record* record);

    /// @brief Construct a Finished message.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] record Record to store the constructed message.
    void constructFinished(const int8_t sideIndex, Record* record);

    /// @brief Enable debug key output.
    ///
    /// @param[in] debug True to enable debug keys, false to disable.
    void setDebugKeys(const bool debug)
    {
        debugKeys_ = debug;
    }

    /// @brief Enable monitoring mode.
    ///
    /// @param[in] value True to enable monitoring, false to disable.
    void setMonitor(const bool value)
    {
        monitor_ = value;
    }

    /// @brief Fetch algorithms that are often used for operations on records.
    void fetchAlgorithms();

    /// @brief Get the hash algorithm used for handshake.
    ///
    /// @return String view of hash algorithm name.
    std::string_view getHashAlgorithm() const;

    /// @brief Get client extensions.
    ///
    /// @return Const reference to client extensions.
    const Extensions& getClientExtensions() const noexcept
    {
        return clientExtensions_;
    }

    /// @brief Get server extensions.
    ///
    /// @return Const reference to server extensions.
    const Extensions& getServerExtensions() const noexcept
    {
        return serverExtensions_;
    }

    /// @brief Get encrypted extensions.
    ///
    /// @return Const reference to encrypted extensions.
    const Extensions& getEncryptedExtensions() const noexcept
    {
        return serverEncExtensions_;
    }

    /// @brief Set the protocol version.
    ///
    /// @param[in] version Protocol version to set.
    inline void setVersion(const ProtocolVersion& version) noexcept
    {
        metaInfo_.version = version;
    }

    /// @brief Set peer's public key.
    ///
    /// @param[in] key Peer's public key.
    void setPublicPeerKey(crypto::KeyPtr key)
    {
        peerPublicKey_ = std::move(key);
    }

    /// @brief Set ephemeral private key for key exchange.
    ///
    /// @param[in] key Ephemeral private key.
    void setEphemeralPrivateKey(crypto::KeyPtr key)
    {
        ephemeralPrivateKey_ = std::move(key);
    }

    /// @brief Get server certificate.
    ///
    /// @return Pointer to server certificate.
    X509Cert* getServerCert() const noexcept
    {
        return serverCert_.get();
    }

    /// @brief Get the current transcript hash.
    ///
    /// @param[out] buffer Buffer to store the hash.
    ///
    /// @return Span containing the transcript hash.
    inline nonstd::span<const uint8_t> getTranscriptHash(nonstd::span<uint8_t> buffer)
    {
        crypto::HashTraits::hashInit(hashCtx_, handshakeHashAlg_);
        crypto::HashTraits::hashUpdate(hashCtx_, handshakeBuffer_);
        return crypto::HashTraits::hashFinal(hashCtx_, buffer);
    }

    /// @brief Post-process a record after handling.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] record Record to post-process.
    void postprocessRecord(const int8_t sideIndex, Record* record);

    /// @brief Update key schedule based on record.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] encrypt True if encrypting, false if decrypting.
    /// @param[in] record Record that triggered the update.
    void keySchedule(const int8_t sideIndex, bool encrypt, Record* record);

    /// @brief Set certificate for a side.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] cert Certificate to set.
    void setCertificate(const int8_t sideIndex, crypto::X509CertPtr cert)
    {
        if (sideIndex == 0)
        {
            clientCert_ = std::move(cert);
        }
        else
        {
            serverCert_ = std::move(cert);
        }
    }

    /// @brief Get session metadata information.
    ///
    /// @return Const reference to metadata.
    inline const MetaInfo& getInfo() const noexcept
    {
        return metaInfo_;
    }

    /// @brief Get write record offset for a side.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    ///
    /// @return Write offset in bytes.
    inline size_t getWriteRecordOffset(const int8_t sideIndex) const
    {
        if (canDecrypt(sideIndex) && metaInfo_.version <= ProtocolVersion::TLSv1_2)
        {
            auto& ctx = (sideIndex == 0 ? clientCipherCtx_ : serverCipherCtx_);
            auto cipher = EVP_CIPHER_CTX_cipher(ctx);
            return crypto::CipherTraits::getExplicitNonceLength(cipher);
        }
        return 0;
    }

private:
    /// @brief Pre-process a record before handling.
    ///
    /// @param[in] sideIndex Side index (0 for client, 1 for server).
    /// @param[in] record Record to pre-process.
    void preprocessRecord(const int8_t sideIndex, Record* record);

private:
    RecordPool& recordPool_;                      ///< Record pool for memory management.
    Record* readingRecord_ = nullptr;             ///< Current reading record.
    casket::RingBuffer<Record*> pendingRecords_;  ///< Incoming records queue.
    casket::RingBuffer<Record*> outgoingRecords_; ///< Outgoing records queue.
    RecordLayer recordLayer_;                     ///< Record layer handler.
    std::vector<uint8_t> handshakeBuffer_;        ///< Buffer for handshake messages.
    crypto::HashCtxPtr hashCtx_;                  ///< Hash context.
    crypto::HashAlg handshakeHashAlg_ = nullptr;  ///< Hash algorithm for handshake.
    crypto::HashAlg hmacHashAlg_ = nullptr;       ///< Hash algorithm for HMAC.
    crypto::CipherAlg cipherAlg_ = nullptr;       ///< Cipher algorithm.
    crypto::MacCtxPtr hmacCtx_;                   ///< HMAC context.
    crypto::CipherCtxPtr clientCipherCtx_;        ///< Client cipher context.
    crypto::CipherCtxPtr serverCipherCtx_;        ///< Server cipher context.
    crypto::X509CertPtr clientCert_;              ///< Client certificate.
    crypto::X509CertPtr serverCert_;              ///< Server certificate.
    crypto::KeyPtr serverKey_;                    ///< Server private key.

    crypto::GroupParams sharedGroupParams_;             ///< Shared group parameters.
    crypto::KeyPtr ephemeralPrivateKey_;                ///< Ephemeral private key.
    crypto::KeyPtr peerPublicKey_;                      ///< Peer's public key.
    MetaInfo metaInfo_;                                 ///< Session metadata.
    std::vector<uint8_t> PMS_;                          ///< Pre-master secret.
    SecretNode keyInfo_;                                ///< Key information.
    std::array<uint8_t, TLS_RANDOM_SIZE> clientRandom_; ///< Client random value.
    std::array<uint8_t, TLS_RANDOM_SIZE> serverRandom_; ///< Server random value.
    Extensions clientExtensions_;                       ///< Client extensions.
    Extensions serverExtensions_;                       ///< Server extensions.
    Extensions serverEncExtensions_;                    ///< Encrypted extensions.
    SequenceNumbers seqnum_;                            ///< Sequence numbers.
    uint8_t cipherState_;                               ///< Cipher state.
    uint8_t canDecrypt_;                                ///< Decryption capability flags.
    uint8_t monitor_;                                   ///< Monitor mode flag.
    uint8_t debugKeys_;                                 ///< Debug keys flag.
};

/// @brief Process a Client Hello message.
///
/// @tparam ExtensionsHandler Type of handler for extensions.
/// @param[in] clientHello The Client Hello message.
/// @param[in] handler Callback for processing extensions.
template <typename ExtensionsHandler>
void Session::processClientHello(const ClientHello& clientHello, ExtensionsHandler&& handler)
{
    metaInfo_.version = clientHello.version;

    assert(clientHello.random.size() == TLS_RANDOM_SIZE);
    std::copy_n(clientHello.random.data(), TLS_RANDOM_SIZE, clientRandom_.data());

    if (metaInfo_.version != ProtocolVersion::SSLv3_0)
    {
        clientExtensions_.deserialize(Side::Client, clientHello.extensions, HandshakeType::ClientHelloCode);

        if constexpr (!std::is_same_v<std::nullptr_t, std::decay_t<ExtensionsHandler>>)
        {
            handler(this, clientExtensions_);
        }
    }
}

/// @brief Process a Server Hello message.
///
/// @tparam ExtensionsHandler Type of handler for extensions.
/// @param[in] serverHello The Server Hello message.
/// @param[in] handler Callback for processing extensions.
template <typename ExtensionsHandler>
void Session::processServerHello(const ServerHello& serverHello, ExtensionsHandler&& handler)
{
    assert(serverHello.random.size() == TLS_RANDOM_SIZE);
    std::copy_n(serverHello.random.data(), TLS_RANDOM_SIZE, serverRandom_.data());

    if (!serverHello.extensions.empty())
    {
        auto type =
            serverHello.isHelloRetryRequest ? HandshakeType::HelloRetryRequestCode : HandshakeType::ServerHelloCode;
        serverExtensions_.deserialize(Side::Server, serverHello.extensions, type);

        if constexpr (!std::is_same_v<std::nullptr_t, std::decay_t<ExtensionsHandler>>)
        {
            handler(this, serverExtensions_);
        }

        if (serverExtensions_.has(tls::ExtensionCode::SupportedVersions))
        {
            auto ext = serverExtensions_.get<tls::SupportedVersions>();
            metaInfo_.version = std::move(ext->versions()[0]);
        }

        if (serverExtensions_.has(tls::ExtensionCode::EncryptThenMac))
        {
            recordLayer_.enableEncryptThenMAC();
        }
    }

    metaInfo_.cipherSuite = CipherSuiteManager::getInstance().getCipherSuiteById(serverHello.cipherSuite);
    casket::ThrowIfFalse(metaInfo_.cipherSuite, "Cipher suite not found");

    if (!monitor_)
    {
        recordLayer_.setVersion(metaInfo_.version);
        fetchAlgorithms();

        if (metaInfo_.version == tls::ProtocolVersion::TLSv1_3 && ephemeralPrivateKey_)
        {
            if (peerPublicKey_)
            {
                /// We know public key by external way
                generateHandshakeSecret(peerPublicKey_, ephemeralPrivateKey_);
            }
            else
            {
                /// We know public key by key share
                auto keyShare = serverExtensions_.get<KeyShare>();
                generateHandshakeSecret(keyShare->getPublicKey(), ephemeralPrivateKey_);
            }
        }
    }
}

} // namespace snet::tls