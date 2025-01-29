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

class Session;

struct SessionCallbacks
{
    using OnRecordReceived = std::function<void(const int8_t, const Record&)>;
    using OnClientHello = std::function<void(Session&, void*)>;
    using OnHandshakeReceived =
        std::function<void(const int8_t, const HandshakeType, std::span<const uint8_t>)>;
    using OnAlertReceived = std::function<void(const int8_t, const Alert&)>;
    using OnAppDataReceived = std::function<void(const int8_t, std::span<const uint8_t>)>;

    OnClientHello onClientHello{nullptr};
    OnRecordReceived onRecord{nullptr};
    OnHandshakeReceived onHandshake{nullptr};
    OnAlertReceived onAlert{nullptr};
    OnAppDataReceived onAppData{nullptr};
};

class Session
{
public:
    Session();

    void processBytes(const int8_t sideIndex, std::span<const uint8_t> inputBytes);

    Record readRecord(const int8_t sideIndex, std::span<const uint8_t> inputBytes,
                      std::vector<uint8_t>& outputBytes, size_t& consumedBytes);

    void processRecord(int8_t sideIndex, const Record& record);

    const ClientRandom& getClientRandom() const;

    void setSecrets(const SecretNode& secrets);

    void setServerInfo(const ServerInfo& serverInfo);

    void setCallbacks(SessionCallbacks callbacks, void* data);

    const ProtocolVersion& version() const
    {
        return version_;
    }

    void PRF(const Secret& secret, std::string_view usage, std::span<const uint8_t> rnd1,
             std::span<const uint8_t> rnd2, std::span<uint8_t> out);

    void generateKeyMaterial(const int8_t sideIndex);

    void generateTLS13KeyMaterial();

    const Extensions& getExtensions(const Side side) const noexcept
    {
        if (side == Side::Client)
        {
            return clientExtensions_;
        }
        else
        {
            return serverExtensions_;
        }
    }

    void updateHash(std::span<const uint8_t> message)
    {
        handshakeHash_.update(message);
    }

    void setClientRandom(const ClientRandom& random)
    {
        clientRandom_ = random;
    }

    void setServerRandom(ServerRandom random)
    {
        serverRandom_ = std::move(random);
    }

    void setSessionID(std::vector<std::uint8_t> sessionID)
    {
        sessionId_ = std::move(sessionID);
    }

    void setVersion(ProtocolVersion version)
    {
        version_ = std::move(version);
    }

    const ProtocolVersion& getVersion() const noexcept
    {
        return version_;
    }

    void setCipherSuite(CipherSuite cipherSuite)
    {
        cipherSuite_ = std::move(cipherSuite);
    }

    const CipherSuite& getCipherSuite() const noexcept
    {
        return cipherSuite_;
    }

    void deserializeExtensions(utils::DataReader& reader, const Side side, const HandshakeType ht)
    {
        if (side == Side::Client)
        {
            clientExtensions_.deserialize(reader, side, ht);
        }
        else if (side == Side::Server)
        {
            serverExtensions_.deserialize(reader, side, ht);
        }
    }

    const Secret& getSecret(const SecretNode::Type type) const
    {
        return secrets_.getSecret(type);
    }

    void setRecordDecoder(bool client2server, std::unique_ptr<RecordDecoder> decoder)
    {
        if (client2server)
        {
            c_to_s = std::move(decoder);
        }
        else
        {
            s_to_c = std::move(decoder);
        }
    }

    void updateKeys(const Side side, const std::vector<std::uint8_t>& key, const std::vector<std::uint8_t>& iv)
    {
        if (side == Side::Client)
        {
            c_to_s->tls13UpdateKeys(key, iv);
        }
        else
        {
            s_to_c->tls13UpdateKeys(key, iv);
        }
    }

    void setPremasterSecret(std::vector<std::uint8_t> pms)
    {
        PMS_ = std::move(pms);
    }

    const ServerInfo& getServerInfo() const
    {
        return serverInfo_;
    }

private:
    void processChangeCipherSpec(int8_t sideIndex, std::span<const uint8_t> data);

    void processAlert(int8_t sideIndex, std::span<const uint8_t> data);

    void processHandshake(int8_t sideIndex, std::span<const uint8_t> data);

    void processApplicationData(int8_t sideIndex, std::span<const uint8_t> data);

private:
    void processHandshakeClientHello(int8_t sideIndex, std::span<const uint8_t> message);

    void processHandshakeServerHello(int8_t sideIndex, std::span<const uint8_t> message);

    void processHandshakeSessionTicket(int8_t sideIndex, std::span<const uint8_t> message);

    void processHandshakeEncryptedExtensions(int8_t sideIndex, std::span<const uint8_t> message);

    void processHandshakeCertificate(int8_t sideIndex, std::span<const uint8_t> message);

    void processHandshakeServerKeyExchange(int8_t sideIndex, std::span<const uint8_t> message);

    void processHandshakeCertificateRequest(int8_t sideIndex, std::span<const uint8_t> message);

    void processHandshakeServerHelloDone(int8_t sideIndex, std::span<const uint8_t> message);

    void processHandshakeCertificateVerify(int8_t sideIndex, std::span<const uint8_t> message);

    void processHandshakeClientKeyExchange(int8_t sideIndex, std::span<const uint8_t> message);

    void processHandshakeFinished(int8_t sideIndex, std::span<const uint8_t> message);

    void processHandshakeKeyUpdate(int8_t sideIndex, std::span<const uint8_t> message);

public:
    SessionCallbacks callbacks_;
    void* userData_;
    ServerInfo serverInfo_;
    ProtocolVersion version_;
    CipherSuite cipherSuite_;
    std::vector<uint8_t> PMS_;
    ClientRandom clientRandom_;
    ServerRandom serverRandom_;
    SecretNode secrets_;
    std::vector<uint8_t> sessionId_;
    std::unique_ptr<RecordDecoder> c_to_s;
    std::unique_ptr<RecordDecoder> s_to_c;
    Extensions clientExtensions_;
    Extensions serverExtensions_;
    HandshakeHash handshakeHash_;
    std::vector<uint8_t> outputBuffer_;
};

} // namespace snet::tls