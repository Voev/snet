#include <snet/crypto/exception.hpp>
#include <snet/crypto/pointers.hpp>

#include <snet/tls/record_decryptor.hpp>
#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/tls/prf.hpp>

#include <snet/utils/print_hex.hpp>

#include <casket/utils/format.hpp>

#include <openssl/core_names.h>

using namespace casket;
using namespace snet::crypto;

namespace snet::tls
{

void RecordDecryptor::handleRecord(const std::int8_t sideIndex, Session* session, Record* record)
{
    ::utils::ThrowIfTrue(session == nullptr, "Session is not setted");

    std::span<const uint8_t> data;

    if (session->canDecrypt(sideIndex) && record->type != RecordType::ChangeCipherSpec)
    {
        session->decrypt(sideIndex, record);
        data = std::span(record->decryptedBuffer.data(), record->decryptedLength);
    }
    else
    {
        data = std::span(record->payload + TLS_HEADER_SIZE, record->expectedLength - TLS_HEADER_SIZE);
    }

    if (record->type == RecordType::ChangeCipherSpec)
    {
        ::utils::ThrowIfFalse(data.size() == 1 && data[0] == 0x01, "Malformed Change Cipher Spec message");

        if (session->getVersion() < ProtocolVersion::TLSv1_3)
        {
            session->generateKeyMaterial(sideIndex);
            session->setCipherState(sideIndex);
        }
    }
    else if (record->type == RecordType::Alert)
    {
        if (session->getCipherState(sideIndex) && !session->canDecrypt(sideIndex))
        {
            return;
        }
        ::utils::ThrowIfTrue(data.size() != 2, ::utils::format("wrong length for alert message: {}", data.size()));
    }
    else if (record->type == RecordType::Handshake)
    {
        if (session->getCipherState(sideIndex) && !session->canDecrypt(sideIndex))
        {
            return;
        }

        utils::DataReader reader("Handshake Message", data);

        session->handshake.type = static_cast<HandshakeType>(reader.get_byte());
        const auto messageLength = reader.get_uint24_t();
        ::utils::ThrowIfFalse(reader.remaining_bytes() == messageLength, "Incorrect length of handshake message");

        switch (session->handshake.type)
        {
        case HandshakeType::HelloRequest:
            /* Not implemented */
            break;
        case HandshakeType::ClientHello:
            processHandshakeClientHello(sideIndex, session, data);
            break;
        case HandshakeType::ServerHello:
            processHandshakeServerHello(sideIndex, session, data);
            break;
        case HandshakeType::HelloVerifyRequest:
            /* Not implemented */
            break;
        case HandshakeType::NewSessionTicket:
            processHandshakeSessionTicket(sideIndex, session, data);
            break;
        case HandshakeType::EndOfEarlyData:
            /* Not implemented */
            break;
        case HandshakeType::EncryptedExtensions:
            processHandshakeEncryptedExtensions(sideIndex, session, data);
            break;
        case HandshakeType::Certificate:
            processHandshakeCertificate(sideIndex, session, data);
            break;
        case HandshakeType::ServerKeyExchange:
            processHandshakeServerKeyExchange(sideIndex, session, data);
            break;
        case HandshakeType::CertificateRequest:
            break;
        case HandshakeType::ServerHelloDone:
            processHandshakeServerHelloDone(sideIndex, session, data);
            break;
        case HandshakeType::CertificateVerify:
            processHandshakeCertificateVerify(sideIndex, session, data);
            break;
        case HandshakeType::ClientKeyExchange:
            processHandshakeClientKeyExchange(sideIndex, session, data);
            break;
        case HandshakeType::Finished:
            processHandshakeFinished(sideIndex, session, data);
            break;
        case HandshakeType::KeyUpdate:
            processHandshakeKeyUpdate(sideIndex, session, data);
            break;
        case HandshakeType::HelloRetryRequest:
            break;
        case HandshakeType::HandshakeCCS:
            break;
        default:
            break;
        }
    }
}

void RecordDecryptor::processHandshakeClientHello(const int8_t sideIndex, Session* session,
                                                  std::span<const uint8_t> message)
{
    ::utils::ThrowIfFalse(sideIndex == 0, "Incorrect side index");

    session->handshake.clientHello.deserialize(message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    session->setVersion(session->handshake.clientHello.legacyVersion);
    session->setClientRandom(session->handshake.clientHello.random);
    session->updateHash(sideIndex, message);
}

void RecordDecryptor::processHandshakeServerHello(const int8_t sideIndex, Session* session,
                                                  std::span<const uint8_t> message)
{
    ::utils::ThrowIfFalse(sideIndex == 1, "Incorrect side index");

    session->handshake.serverHello.deserialize(message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    auto foundCipher = CipherSuiteManager::getInstance().getCipherSuiteById(session->handshake.serverHello.cipherSuite);
    ::utils::ThrowIfFalse(foundCipher.has_value(), "Cipher suite not supported");

    session->setCipherSuite(foundCipher.value());

    auto cipherTraits = CipherSuiteManager::getInstance().fetchCipher(foundCipher.value().getCipherName());
    ::utils::ThrowIfFalse(cipherTraits, "failed to fetch cipher '{}'", foundCipher.value().getCipherName());
    session->setCipherTraits(std::move(cipherTraits));

    if (session->handshake.serverHello.extensions.has(ExtensionCode::SupportedVersions))
    {
        auto ext = session->handshake.serverHello.extensions.get<SupportedVersions>();
        session->setVersion(ext->versions()[0]);
    }

    session->updateHash(sideIndex, message);

    if (session->getVersion() == ProtocolVersion::TLSv1_3)
    {
        session->generateTLS13KeyMaterial();
        session->setCipherState(sideIndex);
    }
}

void RecordDecryptor::processHandshakeCertificate(const int8_t sideIndex, Session* session,
                                                  std::span<const uint8_t> message)
{
    static const char* debugInfo = (sideIndex == 0 ? "Client Certificate" : "Server Certificate");

    if (session->getVersion() == ProtocolVersion::TLSv1_3)
    {
        if (sideIndex == 1)
        {
            session->handshake.serverCertificate.deserialize(message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
            ::utils::ThrowIfFalse(session->handshake.serverCertificate.requestContext.empty(),
                                  "Server Certificate message must not contain a request context");
        }
    }
    else
    {
        utils::DataReader reader(debugInfo, message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        const size_t certsLength = reader.get_uint24_t();
        ::utils::ThrowIfTrue(reader.remaining_bytes() != certsLength, "Certificate: Message malformed");

        while (reader.has_remaining())
        {
            /// Certificate
            reader.get_tls_length_value(3);
        }
        reader.assert_done();
    }

    session->updateHash(sideIndex, message);
}

void RecordDecryptor::processHandshakeSessionTicket(const int8_t sideIndex, Session* session,
                                                    std::span<const uint8_t> message)
{
    ::utils::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
    if (session->getVersion() == ProtocolVersion::TLSv1_3)
    {
        utils::DataReader reader("TLSv1.3 New Session Ticket", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

        // ticket_lifetime_hint
        reader.get_uint32_t();
        // ticket_age_add
        reader.get_uint32_t();
        // ticket nonce
        reader.get_tls_length_value(1);
        // ticket
        reader.get_tls_length_value(2);

        // extensions
        Extensions exts;
        exts.deserialize(reader, Side::Server, HandshakeType::NewSessionTicket);

        reader.assert_done();
    }
    else if (session->getVersion() == ProtocolVersion::TLSv1_2)
    {
        utils::DataReader reader("TLSv1.2 New Session Ticket", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        ::utils::ThrowIfTrue(reader.remaining_bytes() < 6, "Session ticket message too short to be valid");
        reader.get_uint32_t();
        reader.get_range<uint8_t>(2, 0, 65535);
        reader.assert_done();
    }
    else
    {
        throw std::runtime_error("NewSessionTicket can't be in TLS versions below 1.2");
    }
}

void RecordDecryptor::processHandshakeEncryptedExtensions(const int8_t sideIndex, Session* session,
                                                          std::span<const uint8_t> message)
{
    (void)session;

    ::utils::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    session->handshake.encryptedExtensions.deserialize(message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
}

void RecordDecryptor::processHandshakeServerKeyExchange(const int8_t sideIndex, Session* session,
                                                        std::span<const uint8_t> message)
{
    ::utils::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("ServerKeyExchange", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    auto kex = session->getCipherSuite().getKeyExchName();

    if (kex == SN_kx_psk || kex == SN_kx_ecdhe_psk)
    {
        reader.get_string(2, 0, 65535);
    }
    else if (kex == SN_kx_dhe)
    {
        // 3 bigints, DH p, g, Y
        for (size_t i = 0; i != 3; ++i)
        {
            reader.get_range<uint8_t>(2, 1, 65535);
        }
    }
    else if (kex == SN_kx_ecdhe || kex == SN_kx_ecdhe_psk)
    {
        reader.get_byte();                    // curve type
        reader.get_uint16_t();                // curve id
        reader.get_range<uint8_t>(1, 1, 255); // public key
    }
    else if (kex != SN_kx_psk)
    {
        throw std::runtime_error("Server_Key_Exchange: Unsupported kex type");
    }

    auto auth = session->getCipherSuite().getAuthName();
    if (auth == SN_auth_rsa || auth == SN_auth_dss || auth == SN_auth_ecdsa)
    {
        if (session->getVersion() == ProtocolVersion::TLSv1_2)
        {
            reader.get_uint16_t();                  // algorithm
            reader.get_range<uint8_t>(2, 0, 65535); // signature
        }
        else /// < TLSv1.2
        {
            reader.get_range<uint8_t>(2, 0, 65535); // signature
        }
    }

    reader.assert_done();

    session->updateHash(sideIndex, message);
}

void RecordDecryptor::processHandshakeCertificateRequest(const int8_t sideIndex, Session* session,
                                                         std::span<const uint8_t> message)
{
    ::utils::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("Certificate Request", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    ::utils::ThrowIfTrue(reader.remaining_bytes() < 4, "Certificate_Req: Bad certificate request");

    const auto cert_type_codes = reader.get_range_vector<uint8_t>(1, 1, 255);
    const std::vector<uint8_t> algs = reader.get_range_vector<uint8_t>(2, 2, 65534);

    ::utils::ThrowIfTrue(algs.size() % 2 != 0, "Bad length for signature IDs in certificate request");

    const uint16_t purported_size = reader.get_uint16_t();

    ::utils::ThrowIfTrue(reader.remaining_bytes() != purported_size, "Inconsistent length in certificate request");

    while (reader.has_remaining())
    {
        std::vector<uint8_t> name_bits = reader.get_range_vector<uint8_t>(2, 0, 65535);
    }

    reader.assert_done();

    session->updateHash(sideIndex, message);
}

void RecordDecryptor::processHandshakeServerHelloDone(const int8_t sideIndex, Session* session,
                                                      std::span<const uint8_t> message)
{
    ::utils::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
    utils::DataReader reader("Server Hello Done", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    reader.assert_done();
    session->updateHash(sideIndex, message);
}

void RecordDecryptor::processHandshakeCertificateVerify(const int8_t sideIndex, Session* session,
                                                        std::span<const uint8_t> message)
{
    ::utils::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("CertificateVerify", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    reader.get_uint16_t();
    reader.get_range<uint8_t>(2, 0, 65535);
    reader.assert_done();

    session->updateHash(sideIndex, message);
}

void RecordDecryptor::processHandshakeClientKeyExchange(const int8_t sideIndex, Session* session,
                                                        std::span<const uint8_t> message)
{
    ::utils::ThrowIfTrue(sideIndex != 0, "Incorrect side index");
    session->updateHash(sideIndex, message);

    if (!session->getServerInfo().getServerKey())
    {
        return;
    }

    if (session->getCipherSuite().getKeyExchName() == SN_kx_rsa)
    {
        utils::DataReader reader("ClientKeyExchange", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        const std::vector<uint8_t> encryptedPreMaster = reader.get_range<uint8_t>(2, 0, 65535);
        reader.assert_done();

        KeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, session->getServerInfo().getServerKey(), nullptr));
        crypto::ThrowIfFalse(ctx != nullptr);

        crypto::ThrowIfFalse(0 < EVP_PKEY_decrypt_init(ctx));
        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_WITH_TLS_PADDING));

        OSSL_PARAM params[2];
        unsigned int value = session->getVersion().code();
        params[0] = OSSL_PARAM_construct_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, &value);
        params[1] = OSSL_PARAM_construct_end();

        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_params(ctx, params));

        size_t size{0};
        crypto::ThrowIfFalse(0 < EVP_PKEY_decrypt(ctx, nullptr, &size, message.data(), message.size()));

        std::vector<std::uint8_t> pms(size);
        crypto::ThrowIfFalse(
            0 < EVP_PKEY_decrypt(ctx, pms.data(), &size, encryptedPreMaster.data(), encryptedPreMaster.size()));
        pms.resize(size);

        session->setPremasterSecret(std::move(pms));
    }
}

void RecordDecryptor::processHandshakeFinished(const int8_t sideIndex, Session* session,
                                               std::span<const uint8_t> message)
{
    session->updateHash(sideIndex, message);
    session->processFinished(sideIndex);
}

void RecordDecryptor::processHandshakeKeyUpdate(const int8_t sideIndex, Session* session,
                                                std::span<const uint8_t> message)
{
    (void)message;
    session->processKeyUpdate(sideIndex);
}

} // namespace snet::tls