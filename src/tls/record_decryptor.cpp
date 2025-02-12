#include <snet/tls/record_decryptor.hpp>
#include <snet/tls/exception.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

#include <snet/tls/prf.hpp>
#include <snet/utils/print_hex.hpp>

#include <casket/utils/format.hpp>

#include <openssl/core_names.h>

using namespace casket;

namespace snet::tls
{

void RecordDecryptor::setSession(std::shared_ptr<Session> session)
{
    session_ = session;
}

void RecordDecryptor::handleRecord(const std::int8_t sideIndex, const Record& record)
{
    ThrowIfTrue(session_ == nullptr, "Session is not setted");

    auto type = record.type();
    auto data = record.data();

    if (type == RecordType::ChangeCipherSpec)
    {
        ThrowIfFalse(data.size() == 1 && data[0] == 0x01, "Malformed Change Cipher Spec message");

        if (session_->getVersion() < ProtocolVersion::TLSv1_3)
        {
            session_->generateKeyMaterial(sideIndex);
            session_->cipherState(true);
        }
    }
    else if (type == RecordType::Alert)
    {
        if (session_->cipherState() && !session_->canDecrypt(sideIndex == 0))
        {
            return;
        }

        ThrowIfTrue(data.size() != 2,
                    ::utils::format("wrong length for alert message: {}", data.size()));
    }
    else if (type == RecordType::Handshake)
    {
        if (session_->cipherState() && !session_->canDecrypt(sideIndex == 0))
        {
            return;
        }

        utils::DataReader reader("Handshake Message", data);

        const auto messageType = static_cast<tls::HandshakeType>(reader.get_byte());
        const auto messageLength = reader.get_uint24_t();
        ThrowIfFalse(reader.remaining_bytes() == messageLength,
                     "Incorrect length of handshake message");

        switch (messageType)
        {
        case tls::HandshakeType::HelloRequest:
            /* Not implemented */
            break;
        case tls::HandshakeType::ClientHello:
            processHandshakeClientHello(sideIndex, data);
            break;
        case tls::HandshakeType::ServerHello:
            processHandshakeServerHello(sideIndex, data);
            break;
        case tls::HandshakeType::HelloVerifyRequest:
            /* Not implemented */
            break;
        case tls::HandshakeType::NewSessionTicket:
            processHandshakeSessionTicket(sideIndex, data);
            break;
        case tls::HandshakeType::EndOfEarlyData:
            /* Not implemented */
            break;
        case tls::HandshakeType::EncryptedExtensions:
            processHandshakeEncryptedExtensions(sideIndex, data);
            break;
        case tls::HandshakeType::Certificate:
            processHandshakeCertificate(sideIndex, data);
            break;
        case tls::HandshakeType::ServerKeyExchange:
            processHandshakeServerKeyExchange(sideIndex, data);
            break;
        case tls::HandshakeType::CertificateRequest:
            break;
        case tls::HandshakeType::ServerHelloDone:
            processHandshakeServerHelloDone(sideIndex, data);
            break;
        case tls::HandshakeType::CertificateVerify:
            processHandshakeCertificateVerify(sideIndex, data);
            break;
        case tls::HandshakeType::ClientKeyExchange:
            processHandshakeClientKeyExchange(sideIndex, data);
            break;
        case tls::HandshakeType::Finished:
            processHandshakeFinished(sideIndex, data);
            break;
        case tls::HandshakeType::KeyUpdate:
            processHandshakeKeyUpdate(sideIndex, data);
            break;
        case tls::HandshakeType::HelloRetryRequest:
            break;
        case tls::HandshakeType::HandshakeCCS:
            break;
        default:
            break;
        }
    }
}

void RecordDecryptor::processHandshakeClientHello(int8_t sideIndex,
                                                  std::span<const uint8_t> message)
{
    ThrowIfFalse(sideIndex == 0, "Incorrect side index");
    utils::DataReader reader("Client Hello", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    reader.get_byte();
    reader.get_byte();

    session_->setClientRandom(reader.get_fixed<uint8_t>(32));
    session_->setSessionID(reader.get_range<uint8_t>(1, 0, 32));

    /// Read cipher suites
    reader.get_range_vector<uint16_t>(2, 1, 32767);

    /// Read compression methods
    reader.get_range_vector<uint8_t>(1, 1, 255);

    /// Read client extensions
    session_->deserializeExtensions(reader, tls::Side::Client, tls::HandshakeType::ClientHello);

    reader.assert_done();

    session_->updateHash(message);
}

void RecordDecryptor::processHandshakeServerHello(int8_t sideIndex,
                                                  std::span<const uint8_t> message)
{
    ThrowIfFalse(sideIndex == 1, "Incorrect side index");
    utils::DataReader reader("Server Hello", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    session_->setVersion(ProtocolVersion(reader.get_uint16_t()));
    session_->setServerRandom(reader.get_fixed<uint8_t>(32));

    // check for HRR

    /// Session ID
    reader.get_range<uint8_t>(1, 0, 32);

    auto ciphersuite = reader.get_uint16_t();

    /// Compression Method
    reader.get_byte();

    session_->deserializeExtensions(reader, tls::Side::Server, tls::HandshakeType::ServerHello);

    auto foundCipher = CipherSuiteManager::getInstance().getCipherSuiteById(ciphersuite);
    ThrowIfFalse(foundCipher.has_value(), "Cipher suite not found");

    session_->setCipherSuite(foundCipher.value());

    if (session_->getExtensions(Side::Server).has(tls::ExtensionCode::SupportedVersions))
    {
        auto ext = session_->getExtensions(Side::Server).get<tls::SupportedVersions>();
        session_->setVersion(ext->versions()[0]);
    }

    reader.assert_done();

    session_->updateHash(message);

    if (session_->getVersion() == tls::ProtocolVersion::TLSv1_3)
    {
        session_->generateTLS13KeyMaterial();
        session_->cipherState(true);
    }
}

void RecordDecryptor::processHandshakeCertificate(int8_t sideIndex,
                                                  std::span<const uint8_t> message)
{
    static const char* debugInfo = (sideIndex == 0 ? "Client Certificate" : "Server Certificate");
    utils::DataReader reader(debugInfo, message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    if (session_->getVersion() == ProtocolVersion::TLSv1_3)
    {
        auto requestContext = reader.get_range<uint8_t>(1, 0, 255);

        // RFC 8446 4.4.2
        //    [...] in the case of server authentication, this field SHALL be
        //    zero length.
        ThrowIfTrue(sideIndex == 1 && !requestContext.empty(),
                    "Server Certificate message must not contain a request context");

        const size_t certEntriesLength = reader.get_uint24_t();
        ThrowIfTrue(reader.remaining_bytes() != certEntriesLength,
                    "Certificate: Message malformed");

        while (reader.has_remaining())
        {
            /// Cert Entry
            reader.get_tls_length_value(3);
            /// Extensions
            const auto extensionsLength = reader.peek_uint16_t();
            reader.get_fixed<uint8_t>(extensionsLength + 2);
        }
    }
    else
    {
        const size_t certsLength = reader.get_uint24_t();
        ThrowIfTrue(reader.remaining_bytes() != certsLength, "Certificate: Message malformed");

        while (reader.has_remaining())
        {
            /// Certificate
            reader.get_tls_length_value(3);
        }
    }

    reader.assert_done();

    session_->updateHash(message);
}

void RecordDecryptor::processHandshakeSessionTicket(int8_t sideIndex,
                                                    std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 1, "Incorrect side index");
    if (session_->getVersion() == ProtocolVersion::TLSv1_3)
    {
        utils::DataReader reader("TLSv1.3 New Session Ticket",
                                 message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

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
        exts.deserialize(reader, tls::Side::Server, HandshakeType::NewSessionTicket);

        reader.assert_done();
    }
    else if (session_->getVersion() == ProtocolVersion::TLSv1_2)
    {
        utils::DataReader reader("TLSv1.2 New Session Ticket",
                                 message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        ThrowIfTrue(reader.remaining_bytes() < 6, "Session ticket message too short to be valid");
        reader.get_uint32_t();
        reader.get_range<uint8_t>(2, 0, 65535);
        reader.assert_done();
    }
    else
    {
        throw std::runtime_error("NewSessionTicket can't be in TLS versions below 1.2");
    }
}

void RecordDecryptor::processHandshakeEncryptedExtensions(int8_t sideIndex,
                                                          std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("Encrypted Extensions", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    ThrowIfTrue(reader.remaining_bytes() < 2, "Server sent an empty Encrypted Extensions message");
    session_->deserializeExtensions(reader, tls::Side::Server,
                                    tls::HandshakeType::EncryptedExtensions);

    reader.assert_done();
}

void RecordDecryptor::processHandshakeServerKeyExchange(int8_t sideIndex,
                                                        std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("ServerKeyExchange", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    auto kex = session_->getCipherSuite().getKeyExchName();

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

    auto auth = session_->getCipherSuite().getAuthName();
    if (auth == SN_auth_rsa || auth == SN_auth_dss || auth == SN_auth_ecdsa)
    {
        if (session_->getVersion() == ProtocolVersion::TLSv1_2)
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

    session_->updateHash(message);
}

void RecordDecryptor::processHandshakeCertificateRequest(int8_t sideIndex,
                                                         std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("Certificate Request", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    ThrowIfTrue(reader.remaining_bytes() < 4, "Certificate_Req: Bad certificate request");

    const auto cert_type_codes = reader.get_range_vector<uint8_t>(1, 1, 255);
    const std::vector<uint8_t> algs = reader.get_range_vector<uint8_t>(2, 2, 65534);

    ThrowIfTrue(algs.size() % 2 != 0, "Bad length for signature IDs in certificate request");

    const uint16_t purported_size = reader.get_uint16_t();

    ThrowIfTrue(reader.remaining_bytes() != purported_size,
                "Inconsistent length in certificate request");

    while (reader.has_remaining())
    {
        std::vector<uint8_t> name_bits = reader.get_range_vector<uint8_t>(2, 0, 65535);
    }

    reader.assert_done();

    session_->updateHash(message);
}

void RecordDecryptor::processHandshakeServerHelloDone(int8_t sideIndex,
                                                      std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 1, "Incorrect side index");
    utils::DataReader reader("Server Hello Done", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    reader.assert_done();
    session_->updateHash(message);
}

void RecordDecryptor::processHandshakeCertificateVerify(int8_t sideIndex,
                                                        std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("CertificateVerify", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    reader.get_uint16_t();
    reader.get_range<uint8_t>(2, 0, 65535);
    reader.assert_done();

    session_->updateHash(message);
}

void RecordDecryptor::processHandshakeClientKeyExchange(int8_t sideIndex,
                                                        std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 0, "Incorrect side index");
    session_->updateHash(message);

    if (!session_->getServerInfo().getServerKey())
    {
        return;
    }

    if (session_->getCipherSuite().getKeyExchName() == SN_kx_rsa)
    {
        utils::DataReader reader("ClientKeyExchange", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        const std::vector<uint8_t> encryptedPreMaster = reader.get_range<uint8_t>(2, 0, 65535);
        reader.assert_done();

        EvpPkeyCtxPtr ctx(
            EVP_PKEY_CTX_new_from_pkey(nullptr, session_->getServerInfo().getServerKey(), nullptr));
        tls::ThrowIfFalse(ctx != nullptr);

        tls::ThrowIfFalse(0 < EVP_PKEY_decrypt_init(ctx));
        tls::ThrowIfFalse(0 < EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_WITH_TLS_PADDING));

        OSSL_PARAM params[2];
        unsigned int value = session_->getVersion().code();
        params[0] = OSSL_PARAM_construct_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, &value);
        params[1] = OSSL_PARAM_construct_end();

        tls::ThrowIfFalse(0 < EVP_PKEY_CTX_set_params(ctx, params));

        size_t size{0};
        tls::ThrowIfFalse(0 <
                          EVP_PKEY_decrypt(ctx, nullptr, &size, message.data(), message.size()));

        std::vector<std::uint8_t> pms(size);
        tls::ThrowIfFalse(0 < EVP_PKEY_decrypt(ctx, pms.data(), &size, encryptedPreMaster.data(),
                                               encryptedPreMaster.size()));
        pms.resize(size);

        session_->setPremasterSecret(std::move(pms));
    }
}

void RecordDecryptor::processHandshakeFinished(int8_t sideIndex, std::span<const uint8_t> message)
{
    (void)message;
    session_->processFinished(sideIndex);
}

void RecordDecryptor::processHandshakeKeyUpdate(int8_t sideIndex, std::span<const uint8_t> message)
{
    (void)message;

    /// @todo: move it inside session

    std::vector<uint8_t> newsecret;
    std::vector<uint8_t> newkey;
    std::vector<uint8_t> newiv;

    auto cs = session_->getCipherSuite();
    const auto& digest = cs.getHnshDigestName();
    auto md = CipherSuiteManager::getInstance().fetchDigest(digest);
    auto keySize = cs.getKeyBits() / 8;

    if (sideIndex == 0)
    {
        const auto& secret = session_->getSecret(SecretNode::ClientTrafficSecret);
        auto CTS = hkdfExpandLabel(digest, secret, "traffic upd", {}, EVP_MD_get_size(md));
        newkey = hkdfExpandLabel(digest, CTS, "key", {}, keySize);
        newiv = hkdfExpandLabel(digest, CTS, "iv", {}, 12);
        session_->updateKeys(Side::Client, newkey, newiv);
    }
    else
    {
        const auto& secret = session_->getSecret(SecretNode::ServerTrafficSecret);
        auto STS = hkdfExpandLabel(digest, secret, "traffic upd", {}, EVP_MD_get_size(md));
        newkey = hkdfExpandLabel(digest, STS, "key", {}, keySize);
        newiv = hkdfExpandLabel(digest, STS, "iv", {}, 12);

        session_->updateKeys(Side::Server, newkey, newiv);
    }
}

} // namespace snet::tls