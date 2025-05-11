/// @file
/// @brief Declaration of the RecordDecryptor class.

#pragma once
#include <snet/tls/i_record_handler.hpp>
#include <snet/tls/record.hpp>
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
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session The TLS session to handle.
    /// @param record The TLS record to handle.
    void handleRecord(const int8_t sideIndex, Session* session, Record* record) override;

private:
    /// @brief Processes a ClientHello handshake message.
    ///
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session The TLS session to handle.
    /// @param message The handshake message bytes.
    void processHandshakeClientHello(const int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a ServerHello handshake message.
    ///
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session The TLS session to handle.
    /// @param message The handshake message.
    void processHandshakeServerHello(const int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a SessionTicket handshake message.
    ///
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session The TLS session to process.
    /// @param message The handshake message.
    void processHandshakeSessionTicket(const int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes an EncryptedExtensions handshake message.
    ///
    /// @param sideIndex The index indicating the side (client or server).
    /// @param session The TLS session to handle.
    /// @param message The handshake message.
    void processHandshakeEncryptedExtensions(const int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a Certificate handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeCertificate(const int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a ServerKeyExchange handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeServerKeyExchange(const int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a CertificateRequest handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeCertificateRequest(const int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a ServerHelloDone handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeServerHelloDone(const int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a CertificateVerify handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeCertificateVerify(const int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a ClientKeyExchange handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeClientKeyExchange(const int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a Finished handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeFinished(const int8_t sideIndex, Session* session, std::span<const uint8_t> message);

    /// @brief Processes a KeyUpdate handshake message.
    /// @param sideIndex The index indicating the side (client or server).
    /// @param message The handshake message.
    void processHandshakeKeyUpdate(const int8_t sideIndex, Session* session, std::span<const uint8_t> message);
};

} // namespace snet::tls