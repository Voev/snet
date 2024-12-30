#include <cassert>
#include <array>
#include <limits>
#include <memory>

#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/core_names.h>

#include <casket/utils/exception.hpp>
#include <casket/utils/hexlify.hpp>

#include <snet/utils/print_hex.hpp>
#include <snet/utils/memory_viewer.hpp>

#include <snet/tls/session.hpp>
#include <snet/tls/record_decoder.hpp>
#include <snet/tls/prf.hpp>
#include <snet/tls/exception.hpp>
#include <snet/tls/server_info.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

using namespace casket::utils;

namespace snet::tls
{

Session::Session()
    : outputBuffer_(16 * 1024)
{
}

const ClientRandom& Session::getClientRandom() const
{
    return clientRandom_;
}

void Session::setSecrets(const SecretNode& secrets)
{
    secrets_ = secrets;
}

void Session::setServerInfo(const ServerInfo& serverInfo)
{
    serverInfo_.setHostname(serverInfo.getHostname());
    serverInfo_.setIPAddress(serverInfo.getIPAddress());
    serverInfo_.setServerKey(serverInfo.getServerKey());
}

void Session::setCallbacks(SessionCallbacks callbacks, void* userData)
{
    callbacks_ = std::move(callbacks);
    userData_ = userData;
}

void Session::processBytes(const int8_t sideIndex, std::span<const uint8_t> inputBytes)
{
    size_t consumedBytes{0};
    while (inputBytes.size_bytes() > 0)
    {
        auto record = readRecord(sideIndex, inputBytes, outputBuffer_, consumedBytes);
        processRecord(sideIndex, record);
        inputBytes = inputBytes.subspan(consumedBytes);
    }
}

void Session::processHandshakeClientHello(int8_t sideIndex, std::span<const uint8_t> message)
{
    ThrowIfFalse(sideIndex == 0, "Incorrect side index");
    utils::DataReader reader("Client Hello", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    reader.get_byte();
    reader.get_byte();

    clientRandom_ = reader.get_fixed<uint8_t>(32);
    sessionId_ = reader.get_range<uint8_t>(1, 0, 32);

    /// Read cipher suites
    reader.get_range_vector<uint16_t>(2, 1, 32767);

    /// Read compression methods
    reader.get_range_vector<uint8_t>(1, 1, 255);

    /// Read client extensions
    clientExensions_.deserialize(reader, tls::Side::Client, tls::HandshakeType::ClientHello);

    reader.assert_done();

    handshakeHash_.update(message);

    if (callbacks_.onClientHello)
        callbacks_.onClientHello(*this, userData_);
}

void Session::processHandshakeServerHello(int8_t sideIndex, std::span<const uint8_t> message)
{
    ThrowIfFalse(sideIndex == 1, "Incorrect side index");
    utils::DataReader reader("Server Hello", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    version_ = ProtocolVersion(reader.get_uint16_t());
    serverRandom_ = reader.get_fixed<uint8_t>(32);

    // check for HRR

    /// Session ID
    reader.get_range<uint8_t>(1, 0, 32);

    auto ciphersuite = reader.get_uint16_t();

    /// Compression Method
    reader.get_byte();

    serverExensions_.deserialize(reader, tls::Side::Server, tls::HandshakeType::ServerHello);

    auto foundCipher = CipherSuiteManager::getInstance().getCipherSuiteById(ciphersuite);
    ThrowIfFalse(foundCipher.has_value(), "Cipher suite not found");

    cipherSuite_ = foundCipher.value();

    if (serverExensions_.has(tls::ExtensionCode::SupportedVersions))
    {
        auto ext = serverExensions_.get<tls::SupportedVersions>();
        version_ = ext->versions()[0];
    }

    reader.assert_done();

    handshakeHash_.update(message);

    if (version_ == tls::ProtocolVersion::TLSv1_3)
    {
        generateTLS13KeyMaterial();
    }
}

void Session::processHandshakeCertificate(int8_t sideIndex, std::span<const uint8_t> message)
{
    static const char* debugInfo = (sideIndex == 0 ? "Client Certificate" : "Server Certificate");
    utils::DataReader reader(debugInfo, message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    if (version_ == ProtocolVersion::TLSv1_3)
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

    handshakeHash_.update(message);
}

void Session::processHandshakeSessionTicket(int8_t sideIndex, std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 1, "Incorrect side index");
    if (version_ == ProtocolVersion::TLSv1_3)
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
    else if (version_ == ProtocolVersion::TLSv1_2)
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
        throw RuntimeError("NewSessionTicket can't be in TLS versions below 1.2");
    }
}

void Session::processHandshakeEncryptedExtensions(int8_t sideIndex,
                                                  std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("Encrypted Extensions", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    ThrowIfTrue(reader.remaining_bytes() < 2, "Server sent an empty Encrypted Extensions message");
    serverExensions_.deserialize(reader, tls::Side::Server,
                                 tls::HandshakeType::EncryptedExtensions);

    reader.assert_done();
}

void Session::processHandshakeServerKeyExchange(int8_t sideIndex, std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("ServerKeyExchange", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    auto kex = cipherSuite_.getKeyExchName();

    if (kex == SN_kx_psk || kex == SN_kx_ecdhe_psk)
    {
        reader.get_string(2, 0, 65535);
    }

    if (kex == SN_kx_ecdhe)
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
        throw RuntimeError("Server_Key_Exchange: Unsupported kex type");
    }

    auto auth = cipherSuite_.getAuthName();
    if (auth == SN_auth_dss|| auth == SN_auth_ecdsa)
    {
        reader.get_uint16_t();                  // algorithm
        reader.get_range<uint8_t>(2, 0, 65535); // signature
    }

    reader.assert_done();

    handshakeHash_.update(message);
}

void Session::processHandshakeCertificateRequest(int8_t sideIndex, std::span<const uint8_t> message)
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

    handshakeHash_.update(message);
}

void Session::processHandshakeServerHelloDone(int8_t sideIndex, std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 1, "Incorrect side index");
    utils::DataReader reader("Server Hello Done", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    reader.assert_done();
    handshakeHash_.update(message);
}

void Session::processHandshakeCertificateVerify(int8_t sideIndex, std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("CertificateVerify", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    reader.get_uint16_t();
    reader.get_range<uint8_t>(2, 0, 65535);
    reader.assert_done();

    handshakeHash_.update(message);
}

void Session::processHandshakeClientKeyExchange(int8_t sideIndex, std::span<const uint8_t> message)
{
    ThrowIfTrue(sideIndex != 0, "Incorrect side index");
    handshakeHash_.update(message);

    if (!serverInfo_.getServerKey())
    {
        return;
    }

    if (cipherSuite_.getKeyExchName() == SN_kx_rsa)
    {
        utils::DataReader reader("ClientKeyExchange", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        const std::vector<uint8_t> encryptedPreMaster = reader.get_range<uint8_t>(2, 0, 65535);
        reader.assert_done();

        EvpPkeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, serverInfo_.getServerKey(), nullptr));
        tls::ThrowIfFalse(ctx != nullptr);

        tls::ThrowIfFalse(0 < EVP_PKEY_decrypt_init(ctx));
        tls::ThrowIfFalse(0 < EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_WITH_TLS_PADDING));

        OSSL_PARAM params[2];
        unsigned int value = version_.code();
        params[0] = OSSL_PARAM_construct_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, &value);
        params[1] = OSSL_PARAM_construct_end();

        tls::ThrowIfFalse(0 < EVP_PKEY_CTX_set_params(ctx, params));

        size_t size{0};
        tls::ThrowIfFalse(0 <
                          EVP_PKEY_decrypt(ctx, nullptr, &size, message.data(), message.size()));

        PMS_.resize(size);
        tls::ThrowIfFalse(0 < EVP_PKEY_decrypt(ctx, PMS_.data(), &size, encryptedPreMaster.data(),
                                               encryptedPreMaster.size()));

        PMS_.resize(size);
    }
}

void Session::processHandshakeFinished(int8_t sideIndex, std::span<const uint8_t> message)
{
    (void)message;

    if (version_ == tls::ProtocolVersion::TLSv1_3)
    {
        auto keySize = cipherSuite_.getKeyBits() / 8;

        if (sideIndex == 0)
        {
            auto clientWriteKey = hkdfExpandLabel(
                cipherSuite_.getHnshDigestName(),
                secrets_.getSecret(SecretNode::ClientTrafficSecret), "key", {}, keySize);
            auto clientIV =
                hkdfExpandLabel(cipherSuite_.getHnshDigestName(),
                                secrets_.getSecret(SecretNode::ClientTrafficSecret), "iv", {}, 12);

            c_to_s = std::make_unique<RecordDecoder>(cipherSuite_, std::span<uint8_t>(),
                                                     clientWriteKey, clientIV);
            utils::printHex("Client Write key", clientWriteKey);
            utils::printHex("Client IV", clientIV);
        }
        else
        {
            auto serverWriteKey = hkdfExpandLabel(
                cipherSuite_.getHnshDigestName(),
                secrets_.getSecret(SecretNode::ServerTrafficSecret), "key", {}, keySize);
            auto serverIV =
                hkdfExpandLabel(cipherSuite_.getHnshDigestName(),
                                secrets_.getSecret(SecretNode::ServerTrafficSecret), "iv", {}, 12);
            s_to_c = std::make_unique<RecordDecoder>(cipherSuite_, std::span<uint8_t>(),
                                                     serverWriteKey, serverIV);

            utils::printHex("Server Write key", serverWriteKey);
            utils::printHex("Server IV", serverIV);
        }
    }
}

void Session::processHandshakeKeyUpdate(int8_t sideIndex, std::span<const uint8_t> message)
{
    (void)message;

    std::vector<uint8_t> newsecret;
    std::vector<uint8_t> newkey;
    std::vector<uint8_t> newiv;

    auto md = CipherSuiteManager::getInstance().fetchDigest(cipherSuite_.getHnshDigestName());
    auto keySize = cipherSuite_.getKeyBits() / 8;

    if (sideIndex == 0)
    {
        auto CTS = hkdfExpandLabel(EVP_MD_get0_name(md),
                                   secrets_.getSecret(SecretNode::ClientTrafficSecret),
                                   "traffic upd", {}, EVP_MD_get_size(md));
        newkey = hkdfExpandLabel(EVP_MD_get0_name(md), CTS, "key", {}, keySize);
        newiv = hkdfExpandLabel(EVP_MD_get0_name(md), CTS, "iv", {}, 12);
        c_to_s->tls13UpdateKeys(newkey, newiv);
    }
    else
    {
        auto STS = hkdfExpandLabel(EVP_MD_get0_name(md),
                                   secrets_.getSecret(SecretNode::ServerTrafficSecret),
                                   "traffic upd", {}, EVP_MD_get_size(md));
        newkey = hkdfExpandLabel(EVP_MD_get0_name(md), STS, "key", {}, keySize);
        newiv = hkdfExpandLabel(EVP_MD_get0_name(md), STS, "iv", {}, 12);

        s_to_c->tls13UpdateKeys(newkey, newiv);
    }
}

void Session::processHandshake(int8_t sideIndex, std::span<const uint8_t> message)
{
    utils::DataReader reader("Handshake Message", message);

    const auto messageType = static_cast<tls::HandshakeType>(reader.get_byte());
    const auto messageLength = reader.get_uint24_t();
    ThrowIfFalse(reader.remaining_bytes() == messageLength,
                 "Incorrect length of handshake message");

    if (callbacks_.onHandshake)
        callbacks_.onHandshake(sideIndex, messageType, message);

    switch (messageType)
    {
    case tls::HandshakeType::HelloRequest:
        /* Not implemented */
        break;
    case tls::HandshakeType::ClientHello:
        processHandshakeClientHello(sideIndex, message);
        break;
    case tls::HandshakeType::ServerHello:
        processHandshakeServerHello(sideIndex, message);
        break;
    case tls::HandshakeType::HelloVerifyRequest:
        /* Not implemented */
        break;
    case tls::HandshakeType::NewSessionTicket:
        processHandshakeSessionTicket(sideIndex, message);
        break;
    case tls::HandshakeType::EndOfEarlyData:
        /* Not implemented */
        break;
    case tls::HandshakeType::EncryptedExtensions:
        processHandshakeEncryptedExtensions(sideIndex, message);
        break;
    case tls::HandshakeType::Certificate:
        processHandshakeCertificate(sideIndex, message);
        break;
    case tls::HandshakeType::ServerKeyExchange:
        processHandshakeServerKeyExchange(sideIndex, message);
        break;
    case tls::HandshakeType::CertificateRequest:
        break;
    case tls::HandshakeType::ServerHelloDone:
        processHandshakeServerHelloDone(sideIndex, message);
        break;
    case tls::HandshakeType::CertificateVerify:
        processHandshakeCertificateVerify(sideIndex, message);
        break;
    case tls::HandshakeType::ClientKeyExchange:
        processHandshakeClientKeyExchange(sideIndex, message);
        break;
    case tls::HandshakeType::Finished:
        processHandshakeFinished(sideIndex, message);
        break;
    case tls::HandshakeType::KeyUpdate:
        processHandshakeKeyUpdate(sideIndex, message);
        break;
    case tls::HandshakeType::HelloRetryRequest:
        break;
    case tls::HandshakeType::HandshakeCCS:
        break;
    default:
        break;
    }
}

void Session::processChangeCipherSpec(int8_t sideIndex, std::span<const uint8_t> message)
{
    ThrowIfFalse(message.size() == 1 && message[0] == 0x01, "Malformed Change Cipher Spec message");

    if (version_ < tls::ProtocolVersion::TLSv1_3)
    {
        generateKeyMaterial(sideIndex);
    }
}

void Session::processAlert(int8_t sideIndex, std::span<const uint8_t> message)
{
    ThrowIfTrue(message.size() != 2, format("wrong length for alert message: {}", message.size()));

    if (callbacks_.onAlert)
    {
        Alert alert(message);
        callbacks_.onAlert(sideIndex, alert);
    }
}

void Session::processApplicationData(int8_t sideIndex, std::span<const uint8_t> message)
{
    if (callbacks_.onAppData)
    {
        callbacks_.onAppData(sideIndex, message);
    }
}

Record Session::readRecord(const int8_t sideIndex, std::span<const uint8_t> inputBytes,
                           std::vector<uint8_t>& outputBytes, size_t& consumedBytes)
{
    ThrowIfTrue(inputBytes.size() < TLS_HEADER_SIZE, "Inappropriate header size");
    ThrowIfTrue(inputBytes[0] < 20 || inputBytes[0] > 23, "TLS record type had unexpected value");
    ThrowIfTrue(inputBytes[1] != 3 || inputBytes[2] >= 4,
                "TLS record version had unexpected value");

    RecordType recordType = static_cast<RecordType>(inputBytes[0]);
    const ProtocolVersion recordVersion(inputBytes[1], inputBytes[2]);
    const size_t recordSize =
        utils::make_uint16(inputBytes[TLS_HEADER_SIZE - 2], inputBytes[TLS_HEADER_SIZE - 1]);

    ThrowIfTrue(recordSize > MAX_CIPHERTEXT_SIZE, "Received a record that exceeds maximum size");
    ThrowIfTrue(recordSize > inputBytes.size(), "Incorrect record length");
    ThrowIfTrue(recordSize == 0, "Received a empty record");

    consumedBytes = TLS_HEADER_SIZE + recordSize;

    auto version = (version_ != ProtocolVersion()) ? version_ : recordVersion;

    if (version == ProtocolVersion::TLSv1_3 && recordType == RecordType::ApplicationData)
    {
        if (sideIndex == 0 && c_to_s != nullptr)
        {
            c_to_s->tls13Decrypt(recordType, inputBytes.subspan(TLS_HEADER_SIZE, recordSize),
                                 outputBytes);

            uint8_t lastByte = *(outputBytes.end() - 1);
            ThrowIfTrue(lastByte < 20 || lastByte > 23, "TLS record type had unexpected value");
            recordType = static_cast<RecordType>(lastByte);

            return Record(recordType, recordVersion,
                          std::span(outputBytes.begin(), outputBytes.end() - 1));
        }
        else if (sideIndex == 1 && s_to_c != nullptr)
        {
            s_to_c->tls13Decrypt(recordType, inputBytes.subspan(TLS_HEADER_SIZE, recordSize),
                                 outputBytes);

            uint8_t lastByte = *(outputBytes.end() - 1);
            ThrowIfTrue(lastByte < 20 || lastByte > 23, "TLS record type had unexpected value");
            recordType = static_cast<RecordType>(lastByte);

            return Record(recordType, recordVersion,
                          std::span(outputBytes.begin(), outputBytes.end() - 1));
        }
    }
    else if (version <= ProtocolVersion::TLSv1_2)
    {
        if (sideIndex == 0 && c_to_s != nullptr)
        {
            c_to_s->tls1Decrypt(recordType, version,
                                inputBytes.subspan(TLS_HEADER_SIZE, recordSize), outputBytes,
                                serverExensions_.has(ExtensionCode::EncryptThenMac));

            return Record(recordType, recordVersion, outputBytes);
        }
        else if (sideIndex == 1 && s_to_c != nullptr)
        {
            s_to_c->tls1Decrypt(recordType, version,
                                inputBytes.subspan(TLS_HEADER_SIZE, recordSize), outputBytes,
                                serverExensions_.has(ExtensionCode::EncryptThenMac));

            return Record(recordType, recordVersion, outputBytes);
        }
    }

    return Record(recordType, recordVersion, inputBytes.subspan(TLS_HEADER_SIZE, recordSize));
}

void Session::processRecord(int8_t sideIndex, const Record& record)
{
    if (callbacks_.onRecord)
    {
        callbacks_.onRecord(sideIndex, record);
    }

    switch (record.type())
    {
    case tls::RecordType::ChangeCipherSpec:
        processChangeCipherSpec(sideIndex, record.data());
        return;
    case tls::RecordType::Alert:
        processAlert(sideIndex, record.data());
        break;
    case tls::RecordType::Handshake:
        processHandshake(sideIndex, record.data());
        break;
    case tls::RecordType::ApplicationData:
        processApplicationData(sideIndex, record.data());
        break;
    default:
        throw RuntimeError("Unexpected record type " +
                           std::to_string(static_cast<size_t>(record.type())) +
                           " from counterparty");
    }
}

static int tls_iv_length_within_key_block(const EVP_CIPHER* c)
{
    /* If GCM/CCM mode only part of IV comes from PRF */
    if (EVP_CIPHER_get_mode(c) == EVP_CIPH_GCM_MODE)
        return EVP_GCM_TLS_FIXED_IV_LEN;
    else if (EVP_CIPHER_get_mode(c) == EVP_CIPH_CCM_MODE)
        return EVP_CCM_TLS_FIXED_IV_LEN;
    else
        return EVP_CIPHER_get_iv_length(c);
}

void Session::generateKeyMaterial(const int8_t sideIndex)
{
    std::vector<uint8_t> keyBlock;

    if (secrets_.getSecret(SecretNode::MasterSecret).empty())
    {
        Secret masterSecret(48);
        if (serverExensions_.has(tls::ExtensionCode::ExtendedMasterSecret))
        {
            auto sessionHash = handshakeHash_.final(cipherSuite_.getHnshDigestName());
            PRF(PMS_, "extended master secret", sessionHash, {}, masterSecret);
        }
        else
        {
            PRF(PMS_, "master secret", clientRandom_, serverRandom_, masterSecret);
        }
        secrets_.setSecret(SecretNode::MasterSecret, masterSecret);
        utils::printHex("MS", masterSecret);
    }

    auto cipher = CipherSuiteManager::getInstance().fetchCipher(cipherSuite_.getCipherName());

    size_t keySize = EVP_CIPHER_get_key_length(cipher);
    size_t ivSize = tls_iv_length_within_key_block(cipher);

    if (cipherSuite_.isAEAD())
    {
        keyBlock.resize(keySize * 2 + ivSize * 2);
        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", serverRandom_,
            clientRandom_, keyBlock);

        utils::MemoryViewer viewer(keyBlock);
        auto clientWriteKey = viewer.view(keySize);
        auto serverWriteKey = viewer.view(keySize);
        auto clientIV = viewer.view(ivSize);
        auto serverIV = viewer.view(ivSize);

        if (sideIndex == 0)
        {
            c_to_s = std::make_unique<snet::tls::RecordDecoder>();
            c_to_s->initAEAD(cipherSuite_, clientWriteKey, clientIV);
        }
        else
        {
            s_to_c = std::make_unique<snet::tls::RecordDecoder>();
            s_to_c->initAEAD(cipherSuite_, serverWriteKey, serverIV);
        }
    }
    else
    {
        auto md = CipherSuiteManager::getInstance().fetchDigest(cipherSuite_.getDigestName());
        auto macSize = EVP_MD_get_size(md);

        keyBlock.resize(macSize * 2 + keySize * 2 + ivSize * 2);
        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", serverRandom_,
            clientRandom_, keyBlock);

        utils::MemoryViewer viewer(keyBlock);
        auto clientMacKey = viewer.view(macSize);
        auto serverMacKey = viewer.view(macSize);
        auto clientWriteKey = viewer.view(keySize);
        auto serverWriteKey = viewer.view(keySize);
        auto clientIV = viewer.view(ivSize);
        auto serverIV = viewer.view(ivSize);

        if (sideIndex == 0)
        {
            c_to_s = std::make_unique<snet::tls::RecordDecoder>(cipherSuite_, clientMacKey,
                                                                clientWriteKey, clientIV);
        }
        else
        {
            s_to_c = std::make_unique<snet::tls::RecordDecoder>(cipherSuite_, serverMacKey,
                                                                serverWriteKey, serverIV);
        }
    }
}

void Session::generateTLS13KeyMaterial()
{
    if (!secrets_.isValid(ProtocolVersion::TLSv1_3))
    {
        return;
    }

    auto keySize = cipherSuite_.getKeyBits() / 8;

    auto serverHandshakeWriteKey = hkdfExpandLabel(
        cipherSuite_.getHnshDigestName(),
        secrets_.getSecret(SecretNode::ServerHandshakeTrafficSecret), "key", {}, keySize);
    auto serverHandshakeIV =
        hkdfExpandLabel(cipherSuite_.getHnshDigestName(),
                        secrets_.getSecret(SecretNode::ServerHandshakeTrafficSecret), "iv", {}, 12);

    auto clientHandshakeWriteKey = hkdfExpandLabel(
        cipherSuite_.getHnshDigestName(),
        secrets_.getSecret(SecretNode::ClientHandshakeTrafficSecret), "key", {}, keySize);
    auto clientHandshakeIV =
        hkdfExpandLabel(cipherSuite_.getHnshDigestName(),
                        secrets_.getSecret(SecretNode::ClientHandshakeTrafficSecret), "iv", {}, 12);

    utils::printHex("Server Handshake Write key", serverHandshakeWriteKey);
    utils::printHex("Server Handshake IV", serverHandshakeIV);

    utils::printHex("Client Handshake Write key", clientHandshakeWriteKey);
    utils::printHex("Client Handshake IV", clientHandshakeIV);

    c_to_s = std::make_unique<RecordDecoder>(cipherSuite_, std::span<uint8_t>(),
                                             clientHandshakeWriteKey, clientHandshakeIV);
    s_to_c = std::make_unique<RecordDecoder>(cipherSuite_, std::span<uint8_t>(),
                                             serverHandshakeWriteKey, serverHandshakeIV);
}

void Session::PRF(const Secret& secret, std::string_view usage, std::span<const uint8_t> rnd1,
                  std::span<const uint8_t> rnd2, std::span<uint8_t> out)
{
    ThrowIfFalse(version_ <= tls::ProtocolVersion::TLSv1_2, "Invalid TLS version");

    if (version_ <= tls::ProtocolVersion::SSLv3_0)
        ssl3Prf(secret, rnd1, rnd2, out);
    else
    {
        tls1Prf(cipherSuite_.getHnshDigestName(), secret, usage, rnd1, rnd2, out);
    }
}

} // namespace snet::tls