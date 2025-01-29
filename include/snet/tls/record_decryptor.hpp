#pragma once
#include <snet/tls/record_handler.hpp>
#include <snet/tls/session.hpp>

namespace snet::tls
{

class RecordDecryptor final : public RecordHandler
{
public:
    RecordDecryptor() = default;

    ~RecordDecryptor() = default;

    void setSession(std::shared_ptr<Session> session)
    {
        session_ = session;
    }

    void handleRecord(const std::int8_t sideIndex, const Record& record) override;

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

private:
    std::shared_ptr<Session> session_;
};

} // namespace snet::tls