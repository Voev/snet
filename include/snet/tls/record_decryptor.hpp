/// @file
/// @brief Declaration of the RecordDecryptor class.

#pragma once
#include <snet/tls/i_record_handler.hpp>
#include <snet/tls/session.hpp>

namespace snet::tls
{

/// @brief Class for decrypting TLS records.
class RecordDecryptor final : public IRecordHandler
{
public:
    /// @brief Default constructor.
    RecordDecryptor() = default;

    /// @brief Destructor.
    ~RecordDecryptor() = default;

    /// @brief Sets the session for the decryptor.
    /// @param session The session to set.
    void setSession(std::shared_ptr<Session> session);

    /// @brief Handles a TLS record.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param record The TLS record to handle.
    void handleRecord(const std::int8_t sideIndex, const Record& record) override;

private:
    /// @brief Processes a ClientHello handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeClientHello(int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Processes a ServerHello handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeServerHello(int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Processes a SessionTicket handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeSessionTicket(int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Processes an EncryptedExtensions handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeEncryptedExtensions(int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Processes a Certificate handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeCertificate(int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Processes a ServerKeyExchange handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeServerKeyExchange(int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Processes a CertificateRequest handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeCertificateRequest(int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Processes a ServerHelloDone handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeServerHelloDone(int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Processes a CertificateVerify handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeCertificateVerify(int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Processes a ClientKeyExchange handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeClientKeyExchange(int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Processes a Finished handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeFinished(int8_t sideIndex, std::span<const uint8_t> message);

    /// @brief Processes a KeyUpdate handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeKeyUpdate(int8_t sideIndex, std::span<const uint8_t> message);

private:
    std::shared_ptr<Session> session_;
};

} // namespace snet::tls