#include <cassert>
#include <array>
#include <limits>
#include <memory>

#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/x509v3.h>

#include <snet/log/log_manager.hpp>

#include <snet/stream/memory_reader.hpp>
#include <snet/utils/exception.hpp>
#include <snet/utils/hexlify.hpp>

#include <snet/tls/record_decoder.hpp>
#include <snet/tls/session.hpp>
#include <snet/tls/prf.hpp>

namespace snet::tls
{

Session::Session(SessionCallbacks callbacks, void* userData)
    : callbacks_(std::move(callbacks))
    , userData_(userData)
    , i_state(SSL_ST_SENT_NOTHING)
    , r_state(SSL_ST_HANDSHAKE)
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

void Session::PRF(const Secret& secret, std::string_view usage,
                  std::span<const uint8_t> rnd1, std::span<const uint8_t> rnd2,
                  std::span<uint8_t> out)
{
    utils::ThrowIfFalse(version_ <= tls::ProtocolVersion::TLSv1_2,
                        "Invalid TLS version");

    if (version_ <= tls::ProtocolVersion::SSLv3_0)
        ssl3_prf(secret, usage, rnd1, rnd2, out);
    else if (version_ <= tls::ProtocolVersion::TLSv1_1)
        tls_prf(secret, usage, rnd1, rnd2, out);
    else
    {
        auto md = tls::GetMacAlgorithm(cs.getHashAlg());
        tls12_prf(md, secret, usage, rnd1, rnd2, out);
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
    std::vector<uint8_t> clientWriteKey;
    std::vector<uint8_t> serverWriteKey;
    std::vector<uint8_t> clientMacKey;
    std::vector<uint8_t> serverMacKey;
    std::vector<uint8_t> clientIV;
    std::vector<uint8_t> serverIV;
    std::vector<uint8_t> key_block;

    if (secrets_.getSecret(SecretNode::MasterSecret).empty())
    {
        Secret masterSecret(48);
        if (serverExensions.has(tls::Extension_Code::ExtendedMasterSecret))
        {
            auto session_hash = handshakeHash.final(cs.getHashAlg());
            PRF(PMS, "extended master secret", session_hash, {}, masterSecret);
        }
        else
        {
            PRF(PMS, "master secret", clientRandom_, serverRandom_,
                masterSecret);
        }
        secrets_.setSecret(SecretNode::MasterSecret, masterSecret);
        utils::printHex("MS", masterSecret);
    }

    auto cipher = snet::tls::GetEncAlgorithm(cs.getEncAlg());

    size_t keySize = EVP_CIPHER_get_key_length(cipher);
    size_t ivSize = tls_iv_length_within_key_block(cipher);

    if (cs.isAEAD())
    {
        key_block.resize(keySize * 2 + ivSize * 2);
        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion",
            serverRandom_, clientRandom_, key_block);

        clientWriteKey.resize(keySize);
        serverWriteKey.resize(keySize);
        clientIV.resize(ivSize);
        serverIV.resize(ivSize);

        snet::stream::MemoryReader reader(key_block);
        reader.read(clientWriteKey.data(), clientWriteKey.size());
        reader.read(serverWriteKey.data(), serverWriteKey.size());
        reader.read(clientIV.data(), clientIV.size());
        reader.read(serverIV.data(), serverIV.size());

        if (sideIndex == 0)
        {
            c_to_s = std::make_unique<snet::tls::RecordDecoder>();
            c_to_s->initAEAD(cs, clientWriteKey, clientIV);
        }
        else
        {
            s_to_c = std::make_unique<snet::tls::RecordDecoder>();
            s_to_c->initAEAD(cs, serverWriteKey, serverIV);
        }
    }
    else
    {
        auto mac = snet::tls::GetMacAlgorithm(cs.getHashAlg());
        auto macSize = EVP_MD_size(mac);

        key_block.resize(macSize * 2 + keySize * 2 + ivSize * 2);
        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion",
            serverRandom_, clientRandom_, key_block);

        clientMacKey.resize(macSize);
        serverMacKey.resize(macSize);
        clientWriteKey.resize(keySize);
        serverWriteKey.resize(keySize);
        clientIV.resize(ivSize);
        serverIV.resize(ivSize);

        snet::stream::MemoryReader reader(key_block);
        reader.read(clientMacKey.data(), clientMacKey.size());
        reader.read(serverMacKey.data(), serverMacKey.size());
        reader.read(clientWriteKey.data(), clientWriteKey.size());
        reader.read(serverWriteKey.data(), serverWriteKey.size());
        reader.read(clientIV.data(), clientIV.size());
        reader.read(serverIV.data(), serverIV.size());

        if (sideIndex == 0)
        {
            c_to_s = std::make_unique<snet::tls::RecordDecoder>(
                cs, clientMacKey, clientWriteKey, clientIV);
        }
        else
        {
            s_to_c = std::make_unique<snet::tls::RecordDecoder>(
                cs, serverMacKey, serverWriteKey, serverIV);
        }
    }
}

void Session::generateTLS13KeyMaterial()
{
    if (!secrets_.isValid(ProtocolVersion::TLSv1_3))
    {
        log::warning("Unable to generate keying material for TLSv1.3");
        return;
    }

    auto keySize = cs.getStrengthBits() / 8;

    auto md = tls::GetMacAlgorithm(cs.getHashAlg());

    auto serverHandshakeWriteKey = hkdfExpandLabel(
        md, secrets_.getSecret(SecretNode::ServerHandshakeTrafficSecret), "key",
        {}, keySize);
    auto serverHandshakeIV = hkdfExpandLabel(
        md, secrets_.getSecret(SecretNode::ServerHandshakeTrafficSecret), "iv",
        {}, 12);

    auto clientHandshakeWriteKey = hkdfExpandLabel(
        md, secrets_.getSecret(SecretNode::ClientHandshakeTrafficSecret), "key",
        {}, keySize);
    auto clientHandshakeIV = hkdfExpandLabel(
        md, secrets_.getSecret(SecretNode::ClientHandshakeTrafficSecret), "iv",
        {}, 12);

    utils::printHex("Server Handshake Write key", serverHandshakeWriteKey);
    utils::printHex("Server Handshake IV", serverHandshakeIV);

    utils::printHex("Client Handshake Write key", clientHandshakeWriteKey);
    utils::printHex("Client Handshake IV", clientHandshakeIV);

    c_to_s = std::make_unique<RecordDecoder>(
        cs, std::span<uint8_t>(), clientHandshakeWriteKey, clientHandshakeIV);
    s_to_c = std::make_unique<RecordDecoder>(
        cs, std::span<uint8_t>(), serverHandshakeWriteKey, serverHandshakeIV);
}

void Session::processHandshakeClientHello(int8_t sideIndex,
                                          std::span<const uint8_t> message)
{
    utils::ThrowIfFalse(sideIndex == 0, "Incorrect side index");
    stream::DataReader reader("Client Hello", message);

    reader.get_byte();
    reader.get_byte();

    clientRandom_ = reader.get_fixed<uint8_t>(32);
    sessionId_ = reader.get_range<uint8_t>(1, 0, 32);

    /// Read cipher suites
    reader.get_range_vector<uint16_t>(2, 1, 32767);

    /// Read compression methods
    reader.get_range_vector<uint8_t>(1, 1, 255);

    /// Read client extensions
    clientExensions.deserialize(reader, tls::Side::Client,
                                tls::HandshakeType::ClientHello);

    reader.assert_done();

    if (callbacks_.onClientHello)
        callbacks_.onClientHello(*this, userData_);
}

void Session::processHandshakeServerHello(int8_t sideIndex,
                                          std::span<const uint8_t> message)
{
    utils::ThrowIfFalse(sideIndex == 1, "Incorrect side index");
    stream::DataReader reader("Server Hello", message);

    version_ = ProtocolVersion(reader.get_uint16_t());
    serverRandom_ = reader.get_fixed<uint8_t>(32);

    // check for HRR

    /// Session ID
    reader.get_range<uint8_t>(1, 0, 32);

    auto ciphersuite = reader.get_uint16_t();

    /// Compression Method
    reader.get_byte();

    serverExensions.deserialize(reader, tls::Side::Server,
                                tls::HandshakeType::ServerHello);

    cs = CipherSuiteManager::Instance().getCipherSuiteById(ciphersuite);

    if (serverExensions.has(tls::Extension_Code::SupportedVersions))
    {
        auto ext = serverExensions.get<tls::Supported_Versions>();
        version_ = ext->versions()[0];
    }

    reader.assert_done();

    if (version_ == tls::ProtocolVersion::TLSv1_3)
    {
        generateTLS13KeyMaterial();
    }
}

void Session::processHandshakeCertificate(int8_t sideIndex,
                                          std::span<const uint8_t> message)
{
    static const char* debugInfo =
        (sideIndex == 0 ? "Client Certificate" : "Server Certificate");
    stream::DataReader reader(debugInfo, message);

    if (version_ == ProtocolVersion::TLSv1_3)
    {
        auto requestContext = reader.get_range<uint8_t>(1, 0, 255);

        // RFC 8446 4.4.2
        //    [...] in the case of server authentication, this field SHALL be
        //    zero length.
        utils::ThrowIfTrue(
            sideIndex == 1 && !requestContext.empty(),
            "Server Certificate message must not contain a request context");

        const size_t certEntriesLength = reader.get_uint24_t();
        utils::ThrowIfTrue(reader.remaining_bytes() != certEntriesLength,
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
        utils::ThrowIfTrue(reader.remaining_bytes() != certsLength,
                           "Certificate: Message malformed");

        while (reader.has_remaining())
        {
            /// Certificate
            reader.get_tls_length_value(3);
        }
    }

    reader.assert_done();
}

void Session::processHandshakeSessionTicket(int8_t sideIndex,
                                            std::span<const uint8_t> message)
{
    utils::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
    if (version_ == ProtocolVersion::TLSv1_3)
    {
        stream::DataReader reader("TLSv1.3 New Session Ticket", message);

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
        exts.deserialize(reader, tls::Side::Server,
                         HandshakeType::NewSessionTicket);

        reader.assert_done();
    }
    else if (version_ == ProtocolVersion::TLSv1_2)
    {
        stream::DataReader reader("TLSv1.2 New Session Ticket", message);
        utils::ThrowIfTrue(reader.remaining_bytes() < 6,
                           "Session ticket message too short to be valid");
        reader.get_uint32_t();
        reader.get_range<uint8_t>(2, 0, 65535);
        reader.assert_done();
    }
    else
    {
        throw utils::RuntimeError(
            "NewSessionTicket can't be in TLS versions below 1.2");
    }
}

void Session::processHandshakeEncryptedExtensions(
    int8_t sideIndex, std::span<const uint8_t> message)
{
    utils::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    stream::DataReader reader("Encrypted Extensions", message);

    utils::ThrowIfTrue(reader.remaining_bytes() < 2,
                       "Server sent an empty Encrypted Extensions message");
    serverExensions.deserialize(reader, tls::Side::Server,
                                tls::HandshakeType::EncryptedExtensions);

    reader.assert_done();
}

void Session::processHandshakeServerKeyExchange(
    int8_t sideIndex, std::span<const uint8_t> message)
{
    utils::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    stream::DataReader reader("ServerKeyExchange", message);

    auto kex = cs.getKeyExchAlg();

    if (kex == tls::KexAlg::PSK || kex == KexAlg::ECDHE_PSK)
    {
        reader.get_string(2, 0, 65535);
    }

    if (kex == KexAlg::DHE)
    {
        // 3 bigints, DH p, g, Y
        for (size_t i = 0; i != 3; ++i)
        {
            reader.get_range<uint8_t>(2, 1, 65535);
        }
    }
    else if (kex == KexAlg::ECDHE || kex == KexAlg::ECDHE_PSK)
    {
        reader.get_byte();                    // curve type
        reader.get_uint16_t();                // curve id
        reader.get_range<uint8_t>(1, 1, 255); // public key
    }
    else if (kex != KexAlg::PSK)
    {
        throw utils::RuntimeError("Server_Key_Exchange: Unsupported kex type");
    }

    auto auth = cs.getAuthAlg();
    if (auth == AuthAlg::DSS || auth == AuthAlg::ECDSA)
    {
        reader.get_uint16_t();                  // algorithm
        reader.get_range<uint8_t>(2, 0, 65535); // signature
    }

    reader.assert_done();
}

void Session::processHandshakeCertificateRequest(
    int8_t sideIndex, std::span<const uint8_t> message)
{
    utils::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    stream::DataReader reader("Certificate Request", message);

    utils::ThrowIfTrue(reader.remaining_bytes() < 4,
                       "Certificate_Req: Bad certificate request");

    const auto cert_type_codes = reader.get_range_vector<uint8_t>(1, 1, 255);
    const std::vector<uint8_t> algs =
        reader.get_range_vector<uint8_t>(2, 2, 65534);

    utils::ThrowIfTrue(algs.size() % 2 != 0,
                       "Bad length for signature IDs in certificate request");

    const uint16_t purported_size = reader.get_uint16_t();

    utils::ThrowIfTrue(reader.remaining_bytes() != purported_size,
                       "Inconsistent length in certificate request");

    while (reader.has_remaining())
    {
        std::vector<uint8_t> name_bits =
            reader.get_range_vector<uint8_t>(2, 0, 65535);
    }

    reader.assert_done();
}

void Session::processHandshakeServerHelloDone(int8_t sideIndex,
                                              std::span<const uint8_t> message)
{
    utils::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
    stream::DataReader reader("Server Hello Done", message);

    // handshakeHash.update(data);
}

void Session::processHandshakeCertificateVerify(
    int8_t sideIndex, std::span<const uint8_t> message)
{
    utils::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    stream::DataReader reader("CertificateVerify", message);
    reader.get_uint16_t();
    reader.get_range<uint8_t>(2, 0, 65535);
    reader.assert_done();
}

void Session::processHandshakeClientKeyExchange(
    int8_t sideIndex, std::span<const uint8_t> message)
{

    utils::ThrowIfTrue(sideIndex != 0, "Incorrect side index");
    (void)message;

    switch (cs.getKeyExchAlg())
    {
    case snet::tls::KexAlg::RSA:
    case snet::tls::KexAlg::DHE:
        break;
    default:
        break;
    }
}

void Session::processHandshakeFinished(int8_t sideIndex,
                                       std::span<const uint8_t> message)
{
    (void)message;

    if (version_ == tls::ProtocolVersion::TLSv1_3)
    {
        auto keySize = cs.getStrengthBits() / 8;
        auto md = tls::GetMacAlgorithm(cs.getHashAlg());

        if (sideIndex == 0)
        {
            auto clientWriteKey = hkdfExpandLabel(
                md, secrets_.getSecret(SecretNode::ClientTrafficSecret), "key",
                {}, keySize);
            auto clientIV = hkdfExpandLabel(
                md, secrets_.getSecret(SecretNode::ClientTrafficSecret), "iv",
                {}, 12);

            c_to_s = std::make_unique<RecordDecoder>(cs, std::span<uint8_t>(),
                                                     clientWriteKey, clientIV);
            utils::printHex("Client Write key", clientWriteKey);
            utils::printHex("Client IV", clientIV);
        }
        else
        {
            auto serverWriteKey = hkdfExpandLabel(
                md, secrets_.getSecret(SecretNode::ServerTrafficSecret), "key",
                {}, keySize);
            auto serverIV = hkdfExpandLabel(
                md, secrets_.getSecret(SecretNode::ServerTrafficSecret), "iv",
                {}, 12);
            s_to_c = std::make_unique<RecordDecoder>(cs, std::span<uint8_t>(),
                                                     serverWriteKey, serverIV);

            utils::printHex("Server Write key", serverWriteKey);
            utils::printHex("Server IV", serverIV);
        }
    }
}

void Session::processHandshakeKeyUpdate(int8_t sideIndex,
                                        std::span<const uint8_t> message)
{
    (void)message;

    std::vector<uint8_t> newsecret;
    std::vector<uint8_t> newkey;
    std::vector<uint8_t> newiv;

    auto mac = tls::GetMacAlgorithm(cs.getHashAlg());
    auto keySize = cs.getStrengthBits() / 8;

    if (sideIndex == 0)
    {
        auto CTS = hkdfExpandLabel(
            mac, secrets_.getSecret(SecretNode::ClientTrafficSecret),
            "traffic upd", {}, EVP_MD_size(mac));
        newkey = hkdfExpandLabel(mac, CTS, "key", {}, keySize);
        newiv = hkdfExpandLabel(mac, CTS, "iv", {}, 12);
        c_to_s->tls13_update_keys(newkey, newiv);
    }
    else
    {
        auto STS = hkdfExpandLabel(
            mac, secrets_.getSecret(SecretNode::ServerTrafficSecret),
            "traffic upd", {}, EVP_MD_size(mac));
        newkey = hkdfExpandLabel(mac, STS, "key", {}, keySize);
        newiv = hkdfExpandLabel(mac, STS, "iv", {}, 12);

        s_to_c->tls13_update_keys(newkey, newiv);
    }
}

void Session::processHandshake(int8_t sideIndex,
                               std::span<const uint8_t> message)
{
    stream::DataReader reader("Handshake Message", message);

    auto messageType = static_cast<tls::HandshakeType>(reader.get_byte());
    log::warning("{} [{}]", toString(messageType), message.size());

    const auto messageLength = reader.get_uint24_t();
    utils::ThrowIfFalse(reader.remaining_bytes() == messageLength,
                        "Incorrect length of handshake message");

    message = message.subspan(reader.read_so_far());

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
        utils::ThrowIfFalse(message.empty(),
                            "Malformed Server Hello Done Message");
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

void Session::processChangeCipherSpec(int8_t sideIndex,
                                      std::span<const uint8_t> data)
{
    utils::ThrowIfFalse(data.size() == 1 && data[0] == 0x01,
                        "Malformed Change Cipher Spec message");

    if (version_ <= tls::ProtocolVersion::TLSv1_3)
    {
        generateKeyMaterial(sideIndex);
    }
}

void Session::processAlert(int8_t sideIndex, std::span<const uint8_t> data)
{
    (void)sideIndex;
    utils::ThrowIfTrue(
        data.size() != 2,
        utils::format("wrong length for alert message: {}", data.size()));
}

void Session::processApplicationData(int8_t sideIndex,
                                     std::span<const uint8_t> data)
{
    (void)sideIndex;
    utils::printHex(data);
}

Record Session::readRecord(const int8_t sideIndex,
                           std::span<const uint8_t> inputBytes,
                           std::vector<uint8_t>& outputBytes,
                           size_t& consumedBytes)
{
    utils::ThrowIfTrue(inputBytes.size() < TLS_HEADER_SIZE,
                       "Inappropriate header size");
    utils::ThrowIfTrue(inputBytes[0] < 20 || inputBytes[0] > 23,
                       "TLS record type had unexpected value");
    utils::ThrowIfTrue(inputBytes[1] != 3 || inputBytes[2] >= 4,
                       "TLS record version had unexpected value");

    RecordType recordType = static_cast<RecordType>(inputBytes[0]);
    const ProtocolVersion recordVersion(inputBytes[1], inputBytes[2]);
    const size_t recordSize = utils::make_uint16(
        inputBytes[TLS_HEADER_SIZE - 2], inputBytes[TLS_HEADER_SIZE - 1]);

    utils::ThrowIfTrue(recordSize > MAX_CIPHERTEXT_SIZE,
                       "Received a record that exceeds maximum size");
    utils::ThrowIfTrue(recordSize > inputBytes.size(),
                       "Incorrect record length");
    utils::ThrowIfTrue(recordSize == 0, "Received a empty record");

    consumedBytes = TLS_HEADER_SIZE + recordSize;

    auto version = (version_ != ProtocolVersion()) ? version_ : recordVersion;

    if (version == ProtocolVersion::TLSv1_3 &&
        recordType == RecordType::ApplicationData)
    {
        if (sideIndex == 0)
        {
            c_to_s->tls13_decrypt(
                recordType, inputBytes.subspan(TLS_HEADER_SIZE, recordSize),
                outputBytes);
        }
        else
        {
            s_to_c->tls13_decrypt(
                recordType, inputBytes.subspan(TLS_HEADER_SIZE, recordSize),
                outputBytes);
        }

        uint8_t lastByte = *(outputBytes.end() - 1);

        utils::ThrowIfTrue(lastByte < 20 || lastByte > 23,
                           "TLS record type had unexpected value");

        recordType = static_cast<RecordType>(lastByte);

        return Record(recordType, recordVersion,
                      std::span(outputBytes.begin(), outputBytes.end() - 1));
    }
    else if (version <= ProtocolVersion::TLSv1_2)
    {
        if (sideIndex == 0 && c_to_s != nullptr)
        {
            c_to_s->tls_decrypt(recordType, version,
                                inputBytes.subspan(TLS_HEADER_SIZE, recordSize),
                                outputBytes);

            return Record(recordType, recordVersion, outputBytes);
        }
        else if (sideIndex == 1 && s_to_c != nullptr)
        {
            s_to_c->tls_decrypt(recordType, version,
                                inputBytes.subspan(TLS_HEADER_SIZE, recordSize),
                                outputBytes);

            return Record(recordType, recordVersion, outputBytes);
        }
    }

    return Record(recordType, recordVersion,
                  inputBytes.subspan(TLS_HEADER_SIZE, recordSize));
}

void Session::processRecord(int8_t sideIndex, const Record& record)
{
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
        throw utils::RuntimeError(
            "Unexpected record type " +
            std::to_string(static_cast<size_t>(record.type())) +
            " from counterparty");
    }
}

} // namespace snet::tls