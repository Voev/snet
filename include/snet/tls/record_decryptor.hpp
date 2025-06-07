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

    /// @brief Handles a TLS record.
    ///
    /// @param[in] sideIndex Index indicating the side (client or server).
    /// @param[in] session TLS session.
    /// @param[in] record TLS record.
    ///
    void handleRecord(const std::int8_t sideIndex, Session* session, Record* record) override;

private:
    /// @brief Processes a ClientHello handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session TLS session.
    /// @param message The handshake message.
    void processHandshakeClientHello(const std::int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a ServerHello handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session TLS session.
    /// @param message The handshake message.
    void processHandshakeServerHello(const std::int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a SessionTicket handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session TLS session.
    /// @param message The handshake message.
    void processHandshakeSessionTicket(const std::int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes an EncryptedExtensions handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session TLS session.
    /// @param message The handshake message.
    void processHandshakeEncryptedExtensions(const std::int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a Certificate handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session TLS session.
    /// @param message The handshake message.
    void processHandshakeCertificate(const std::int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a ServerKeyExchange handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session TLS session.
    /// @param message The handshake message.
    void processHandshakeServerKeyExchange(const std::int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a CertificateRequest handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session TLS session.
    /// @param message The handshake message.
    void processHandshakeCertificateRequest(const std::int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a ServerHelloDone handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session TLS session.
    /// @param message The handshake message.
    void processHandshakeServerHelloDone(const std::int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a CertificateVerify handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session TLS session.
    /// @param message The handshake message.
    void processHandshakeCertificateVerify(const std::int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a ClientKeyExchange handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session TLS session.
    /// @param message The handshake message.
    void processHandshakeClientKeyExchange(const std::int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a Finished handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session TLS session.
    /// @param message The handshake message.
    void processHandshakeFinished(const std::int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a KeyUpdate handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session TLS session.
    /// @param message The handshake message.
    void processHandshakeKeyUpdate(const std::int8_t sideIndex, Session* session, std::span<const uint8_t> message);
};

} // namespace snet::tls