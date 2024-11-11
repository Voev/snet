#pragma once
#include <vector>
#include <array>
#include <span>
#include <memory>
#include <string>
#include <functional>
#include <unordered_map>

#include <snet/tls/record_decoder.hpp>
#include <snet/tls/secret_node_manager.hpp>
#include <snet/tls/client_random.hpp>
#include <snet/tls/extensions.hpp>
#include <snet/tls/handshake_hash.hpp>
#include <snet/tls/record.hpp>

namespace snet::tls
{

class Session;

struct SessionCallbacks
{
    typedef void (*OnClientHello)(Session& session, void* userData);

    OnClientHello onClientHello = nullptr;
};

struct Session
{
public:
    Session(SessionCallbacks callbacks = SessionCallbacks(),
            void* userData = nullptr);

    Record readRecord(const int8_t sideIndex,
                      std::span<const uint8_t> inputBytes,
                      std::vector<uint8_t>& outputBytes, size_t& consumedBytes);

    void processRecord(int8_t sideIndex, const Record& record);

    const ClientRandom& getClientRandom() const;

    void setSecrets(const SecretNode& secrets);

private:
    void processChangeCipherSpec(int8_t sideIndex,
                                 std::span<const uint8_t> data);

    void processAlert(int8_t sideIndex, std::span<const uint8_t> data);

    void processHandshake(int8_t sideIndex, std::span<const uint8_t> data);

    void processApplicationData(int8_t sideIndex,
                                std::span<const uint8_t> data);

private:
    void processHandshakeClientHello(int8_t sideIndex,
                                     std::span<const uint8_t> message);

    void processHandshakeServerHello(int8_t sideIndex,
                                     std::span<const uint8_t> message);

    void processHandshakeSessionTicket(int8_t sideIndex,
                                       std::span<const uint8_t> message);

    void processHandshakeEncryptedExtensions(int8_t sideIndex,
                                             std::span<const uint8_t> message);

    void processHandshakeCertificate(int8_t sideIndex,
                                     std::span<const uint8_t> message);

    void processHandshakeServerKeyExchange(int8_t sideIndex,
                                           std::span<const uint8_t> message);

    void processHandshakeCertificateRequest(int8_t sideIndex,
                                            std::span<const uint8_t> message);

    void processHandshakeServerHelloDone(int8_t sideIndex,
                                         std::span<const uint8_t> message);

    void processHandshakeCertificateVerify(int8_t sideIndex,
                                           std::span<const uint8_t> message);

    void processHandshakeClientKeyExchange(int8_t sideIndex,
                                           std::span<const uint8_t> message);

    void processHandshakeFinished(int8_t sideIndex,
                                  std::span<const uint8_t> message);

    void processHandshakeKeyUpdate(int8_t sideIndex,
                                   std::span<const uint8_t> message);

private:
    void PRF(const Secret& secret, std::string_view usage,
             std::span<const uint8_t> rnd1, std::span<const uint8_t> rnd2,
             std::span<uint8_t> out);

    void generateKeyMaterial(const int8_t sideIndex);

    void generateTLS13KeyMaterial();

public:
    SessionCallbacks callbacks_;
    void* userData_;
    ProtocolVersion version_;
    CipherSuite cipherSuite_;
    std::vector<uint8_t> PMS_;
    ClientRandom clientRandom_;
    ServerRandom serverRandom_;
    SecretNode secrets_;
    std::vector<uint8_t> sessionId_;
    std::unique_ptr<RecordDecoder> c_to_s;
    std::unique_ptr<RecordDecoder> s_to_c;
    Extensions clientExensions_;
    Extensions serverExensions_;
    HandshakeHash handshakeHash_;
};

} // namespace snet::tls