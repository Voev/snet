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

#include <snet/tls/alert.hpp>
#include <snet/tls/secret_node_manager.hpp>
#include <snet/tls/client_random.hpp>
#include <snet/tls/extensions.hpp>
#include <snet/tls/record.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/record_pool.hpp>
#include <snet/tls/record_layer.hpp>
#include <snet/tls/record_processor.hpp>
#include <snet/tls/cipher_suite.hpp>
#include <snet/tls/cipher_suite_manager.hpp>
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

    size_t readRecords(nonstd::span<const uint8_t> input);

    size_t writeRecords(nonstd::span<uint8_t> output);

    size_t processRecords(const int8_t sideIndex, nonstd::span<const std::uint8_t> input);

    /// @brief Processes all pending records in the queue with a custom handler.
    /// @tparam Handler A callable type that handles individual records.
    ///
    /// @param[in] sideIndex Indicates which side's records to process (0 for client, 1 for server).
    /// @param[in] recordHandler Callback function or functor that processes each record
    ///                      Signature: void(const int8_t, Record*).
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

                keySchedule(sideIndex, record);
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
    bool addOutgoingRecord(const int8_t sideIndex, Record* record)
    {
        if (record)
        {
            postprocessRecord(sideIndex, record);

            if (record->mustBeEncrypted())
            {
                encrypt(sideIndex, record);
            }

            keySchedule(sideIndex, record);

            return outgoingRecords_.push(record);
        }
        return false;
    }

    /// @brief Checks if the session can decrypt data.
    ///
    /// @param[in] client2server Indicates if the direction is client to server.
    ///
    /// @return true - if session can decrypt data, false - otherwise.
    bool canDecrypt(const int8_t sideIndex) const noexcept;

    /// @brief Encrypt a TLS record.
    ///
    /// @param[in] sideIndex Index indicating the side (client or server).
    /// @param[in] record TLS record.
    ///
    void encrypt(const int8_t sideIndex, Record* record);

    /// @brief Decrypt a TLS record.
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
    void PRF(nonstd::span<const uint8_t> secret, std::string_view usage, nonstd::span<const uint8_t> rnd1,
             nonstd::span<const uint8_t> rnd2, nonstd::span<uint8_t> out);

    /// @brief Generates the handshake secret using ECDHE key exchange.
    ///
    /// @param[in] publicKey The peer's public key for key agreement.
    /// @param[in] privateKey The local private key for key agreement.
    ///
    void generateHandshakeSecret(Key* publicKey, Key* privateKey);

    /// @brief Generates the TLS 1.3 master secret from the handshake secret.
    /// @details Derives the master secret using HKDF-Extract and HKDF-Expand
    ///          operations as specified in RFC 8446.
    void generateTLSv13MasterSecret();

    /// @brief Derives the handshake traffic secrets for encrypting handshake messages.
    /// @details Generates the client_handshake_traffic_secret and
    ///          server_handshake_traffic_secret used for encrypting handshake records.
    void generateHandshakeTrafficSecrets();

    /// @brief Derives the application traffic secrets for encrypting application data
    /// @details Generates the client_application_traffic_secret_0 and
    ///          server_application_traffic_secret_0 used for encrypting
    ///          application data records.
    void generateApplicationTrafficSecrets();

    /// @brief Generates key material for the session.
    /// @param sideIndex The index indicating the side (client or server).
    void generateKeyMaterial(const int8_t sideIndex);

    /// @brief Generates the handshake keys and initialization vectors.
    ///
    void generateHandshakeKeyAndIv();

    /// @brief Generates the application data keys and initialization vectors.
    ///
    /// @param[in] sideIndex Indicates which side's keys to generate (0 for client, 1 for server).
    ///
    void generateApplicationKeyAndIv(const int8_t sideIndex);

    /// @brief Gets the protocol version of the session.
    /// @return The protocol version.
    const ProtocolVersion& getVersion() const noexcept;

    /// @brief Gets the cipher suite of the session.
    /// @return The cipher suite.
    const CipherSuite& getCipherSuite() const noexcept;

    /// @brief Sets the secrets for the session.
    /// @param secrets The secrets to set.
    void setSecrets(const SecretNode* secrets);

    /// @brief Sets the premaster secret for the session.
    /// @param pms The premaster secret to set.
    void setPremasterSecret(std::vector<std::uint8_t> pms);

    /// @brief Sets the server private key for the session.
    ///
    /// @param[in] key Server private key.
    ///
    void setServerKey(Key* key);

    template <typename ExtensionsHandler = std::nullptr_t>
    void processClientHello(const ClientHello& clientHello, ExtensionsHandler&& handler = nullptr);

    template <typename ExtensionsHandler = std::nullptr_t>
    void processServerHello(const ServerHello& serverHello, ExtensionsHandler&& handler = nullptr);

    void processEncryptedExtensions(const EncryptedExtensions& encryptedExtensions);

    void processNewSessionTicket(const NewSessionTicket& sessionTicket);

    void processCertificate(const int8_t sideIndex, const Certificate& certificate);

    void processCertificateRequest(const int8_t sideIndex, const CertificateRequest& certRequest);

    void processCertificateVerify(const int8_t sideIndex, const CertificateVerify& certVerify);

    void processServerKeyExchange(const ServerKeyExchange& keyExchange);

    void processClientKeyExchange(const ClientKeyExchange& keyExchange);

    /// @brief Handles Finished message to create key material if it's necessary.
    /// @param sideIndex The side (client or server).
    void processFinished(const int8_t sideIndex, const Finished& finished);

    /// @brief Handles KeyUpdate message to update key material if it's necessary.
    /// @param sideIndex The side (client or server).
    void processKeyUpdate(const int8_t sideIndex, nonstd::span<const uint8_t> message);

    void constructClientHello(ClientHello& clientHello);

    void constructCertificate(const int8_t sideIndex, Record* record);

    void constructCertificateVerify(const int8_t sideIndex, Record* record);

    void constructFinished(const int8_t sideIndex, Record* record);


    void setDebugKeys(const bool debug)
    {
        debugKeys_ = debug;
    }

    void setMonitor(const bool value)
    {
        monitor_ = value;
    }

    /// @brief Fetch algorithms that are often used for operations on records.
    ///
    void fetchAlgorithms();

    std::string_view getHashAlgorithm() const;

    const Extensions& getClientExtensions() const noexcept
    {
        return clientExtensions_;
    }

    const Extensions& getServerExtensions() const noexcept
    {
        return serverExtensions_;
    }

    const Extensions& getEncryptedExtensions() const noexcept
    {
        return serverEncExtensions_;
    }

    void setPublicPeerKey(crypto::KeyPtr key)
    {
        publicPeerKey_ = std::move(key);
    }

    void setEphemeralPrivateKey(crypto::KeyPtr key)
    {
        ephemeralPrivateKey_ = std::move(key);
    }

    X509Cert* getServerCert() const noexcept
    {
        return serverCert_.get();
    }

    inline nonstd::span<const uint8_t> getTranscriptHash(nonstd::span<uint8_t> buffer)
    {
        crypto::HashTraits::hashInit(hashCtx_, handshakeHashAlg_);
        crypto::HashTraits::hashUpdate(hashCtx_, handshakeBuffer_);
        return crypto::HashTraits::hashFinal(hashCtx_, buffer);
    }

    void postprocessRecord(const int8_t sideIndex, Record* record);

    void keySchedule(const int8_t sideIndex, Record* record);

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

private:
    void preprocessRecord(const int8_t sideIndex, Record* record);

private:
    RecordPool& recordPool_;
    Record* readingRecord_ = nullptr;             ///< Current reading record.
    casket::RingBuffer<Record*> pendingRecords_;  ///< Incoming records queue.
    casket::RingBuffer<Record*> outgoingRecords_; ///< Outgoing records queue.
    RecordLayer recordLayer_;
    std::vector<uint8_t> handshakeBuffer_;
    crypto::HashCtxPtr hashCtx_;
    crypto::HashAlg handshakeHashAlg_ = nullptr;
    crypto::HashAlg hmacHashAlg_ = nullptr; ///< Fetched hash algorithm by cipher suite used in HMAC
    crypto::CipherAlg cipherAlg_ = nullptr; ///< Fetched cipher algorithm by cipher suite
    crypto::MacCtxPtr hmacCtx_;             ///< HMAC context for TLSv1.2 (and earlier) non-AEAD cipher suites
    crypto::CipherCtxPtr clientCipherCtx_;
    crypto::CipherCtxPtr serverCipherCtx_;
    crypto::X509CertPtr clientCert_;
    crypto::X509CertPtr serverCert_;
    crypto::KeyPtr serverKey_;

    crypto::KeyPtr ephemeralPrivateKey_;
    crypto::KeyPtr publicPeerKey_;
    RecordProcessor processor_;
    MetaInfo metaInfo_;
    std::vector<uint8_t> PMS_;
    SecretNode keyInfo_;
    std::array<uint8_t, TLS_RANDOM_SIZE> clientRandom_;
    std::array<uint8_t, TLS_RANDOM_SIZE> serverRandom_;
    Extensions clientExtensions_;
    Extensions serverExtensions_;
    Extensions serverEncExtensions_;
    SequenceNumbers seqnum_;
    uint8_t cipherState_;
    uint8_t canDecrypt_;
    uint8_t monitor_;
    uint8_t debugKeys_;
};

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

    if (processor_)
    {
        for (const auto& handler : *processor_)
        {
            handler->handleClientHello(clientHello, this);
        }
    }
}

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
            if (publicPeerKey_)
            {
                /// We know public key by external way
                generateHandshakeSecret(publicPeerKey_, ephemeralPrivateKey_);
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