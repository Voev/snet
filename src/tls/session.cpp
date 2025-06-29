#include <cassert>
#include <array>
#include <limits>
#include <memory>

#include <casket/utils/exception.hpp>
#include <casket/utils/hexlify.hpp>
#include <casket/log/color.hpp>

#include <snet/utils/print_hex.hpp>
#include <snet/utils/memory_viewer.hpp>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/cipher_context.hpp>

#include <snet/tls/session.hpp>
#include <snet/tls/record_decoder.hpp>
#include <snet/tls/prf.hpp>
#include <snet/tls/server_info.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

#include <openssl/core_names.h>

inline std::string Colorize(std::string_view text, std::string_view color = casket::lRed)
{
    return casket::format("[{}{}{}]", color, text, casket::resetColor);
}

namespace snet::tls
{

Session::Session(RecordPool& recordPool)
    : recordPool_(recordPool)
    , cipherState_(0)
    , canDecrypt_(0)
    , debugKeys_(0)
{
}

bool Session::getCipherState(const std::int8_t sideIndex) const noexcept
{
    return ((cipherState_ & 0x1) && sideIndex == 0) || ((cipherState_ & 0x2) && sideIndex == 1);
}

bool Session::canDecrypt(const std::int8_t sideIndex) const noexcept
{
    return ((canDecrypt_ & 0x1) && sideIndex == 0) || ((canDecrypt_ & 0x2) && sideIndex == 1);
}

size_t Session::processRecords(const int8_t sideIndex, cpp::span<const uint8_t> input)
{
    casket::ThrowIfTrue(input.empty(), "invalid input data");

    size_t processedLength{0};

    while (processedLength < input.size())
    {
        if (!readingRecord)
        {
            if (input.size() < processedLength + TLS_HEADER_SIZE)
            {
                break;
            }

            readingRecord = recordPool_.acquire();
            if (!readingRecord)
            {
                return processedLength;
            }

            readingRecord->deserializeHeader(input.subspan(processedLength, TLS_HEADER_SIZE));
        }

        const size_t payloadProcessed = readingRecord->initPayload(input.subspan(processedLength));
        processedLength += payloadProcessed;

        if (readingRecord->isFullyAssembled() && processor_)
        {
            preprocessRecord(sideIndex, readingRecord);

            for (const auto& handler : *processor_)
            {
                handler->handleRecord(sideIndex, this, readingRecord);
            }

            postprocessRecord(sideIndex, readingRecord);

            recordPool_.release(std::exchange(readingRecord, nullptr));
        }
    }

    if (readingRecord)
    {
        if (processedLength == 0)
        {
            recordPool_.release(std::exchange(readingRecord, nullptr));
        }
        return 0;
    }

    return processedLength;
}

void Session::preprocessRecord(const std::int8_t sideIndex, Record* record)
{
    cpp::span<const uint8_t> data;

    if (canDecrypt(sideIndex) && record->type != RecordType::ChangeCipherSpec)
    {
        decrypt(sideIndex, record);
        data = record->getDecryptedData();
    }
    else
    {
        data = record->getData().subspan(TLS_HEADER_SIZE);
    }

    if (record->getType() == RecordType::ChangeCipherSpec)
    {
        casket::ThrowIfFalse(data.size() == 1 && data[0] == 0x01, "Malformed Change Cipher Spec message");

        if (getVersion() < ProtocolVersion::TLSv1_3)
        {
            generateKeyMaterial(sideIndex);
        }
    }
    else if (record->getType() == RecordType::Alert)
    {
        if (getCipherState(sideIndex) && !canDecrypt(sideIndex))
        {
            return;
        }

        casket::ThrowIfTrue(data.size() != 2, "wrong length for alert message: {}", data.size());
    }
    else if (record->getType() == RecordType::Handshake)
    {
        if (getCipherState(sideIndex) && !canDecrypt(sideIndex))
        {
            return;
        }

        utils::DataReader reader("Handshake Message", data);

        const auto messageType = static_cast<HandshakeType>(reader.get_byte());
        const auto messageLength = reader.get_uint24_t();
        casket::ThrowIfFalse(reader.remaining_bytes() == messageLength, "Incorrect length of handshake message");

        switch (messageType)
        {
        case HandshakeType::HelloRequest:
            /* Not implemented */
            break;
        case HandshakeType::ClientHello:
            processClientHello(sideIndex, data);
            break;
        case HandshakeType::ServerHello:
            processServerHello(sideIndex, data);
            break;
        case HandshakeType::HelloVerifyRequest:
            /* Not implemented */
            break;
        case HandshakeType::NewSessionTicket:
            processSessionTicket(sideIndex, data);
            break;
        case HandshakeType::EndOfEarlyData:
            /* Not implemented */
            break;
        case HandshakeType::EncryptedExtensions:
            processEncryptedExtensions(sideIndex, data);
            break;
        case HandshakeType::Certificate:
            processCertificate(sideIndex, data);
            break;
        case HandshakeType::ServerKeyExchange:
            processServerKeyExchange(sideIndex, data);
            break;
        case HandshakeType::CertificateRequest:
            break;
        case HandshakeType::ServerHelloDone:
            processServerHelloDone(sideIndex, data);
            break;
        case HandshakeType::CertificateVerify:
            processCertificateVerify(sideIndex, data);
            break;
        case HandshakeType::ClientKeyExchange:
            processClientKeyExchange(sideIndex, data);
            break;
        case HandshakeType::Finished:
            processFinished(sideIndex, data);
            break;
        case HandshakeType::KeyUpdate:
            processKeyUpdate(sideIndex, data);
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

void Session::postprocessRecord(const std::int8_t sideIndex, Record* record)
{
    if (getVersion() < ProtocolVersion::TLSv1_3)
    {
        if (record->getType() == RecordType::ChangeCipherSpec)
        {
            cipherState_ |= (sideIndex == 0 ? 1 : 2);
        }
    }
    else
    {
        /// @todo: pay attention to the HelloRetryRequest
        cipherState_ |= (sideIndex == 0 ? 1 : 2);
    }
}

bool Session::canDecrypt(bool client2server) const noexcept
{
    return (client2server && clientToServer_.isInited()) || (!client2server && serverToClient_.isInited());
}

void Session::decrypt(const std::int8_t sideIndex, Record* record)
{
    auto version = (version_ != ProtocolVersion()) ? version_ : record->getVersion();
    auto input = record->getData();
    auto encryptThenMAC = handshake_.serverHello.extensions.has(ExtensionCode::EncryptThenMac);

    if (sideIndex == 0 && clientToServer_.isInited())
    {
        if (version == ProtocolVersion::TLSv1_3)
        {
            record->decryptedData = clientToServer_.tls13Decrypt(record->getType(), input.subspan(TLS_HEADER_SIZE),
                                                                 record->decryptedBuffer);
        }
        else if (version <= ProtocolVersion::TLSv1_2)
        {
            record->decryptedData = clientToServer_.tls1Decrypt(
                record->getType(), version, input.subspan(TLS_HEADER_SIZE), record->decryptedBuffer, encryptThenMAC);
        }
    }
    else if (sideIndex == 1 && serverToClient_.isInited())
    {
        if (version == ProtocolVersion::TLSv1_3)
        {
            record->decryptedData = serverToClient_.tls13Decrypt(record->getType(), input.subspan(TLS_HEADER_SIZE),
                                                                 record->decryptedBuffer);
        }
        else if (version <= ProtocolVersion::TLSv1_2)
        {
            record->decryptedData = serverToClient_.tls1Decrypt(
                record->getType(), version, input.subspan(TLS_HEADER_SIZE), record->decryptedBuffer, encryptThenMAC);
        }
    }

    if (version == ProtocolVersion::TLSv1_3)
    {
        uint8_t lastByte = record->decryptedData.back();
        casket::ThrowIfTrue(lastByte < 20 || lastByte > 23, "TLSv1.3 record type had unexpected value '{}'", lastByte);

        record->type = static_cast<RecordType>(lastByte);
        record->decryptedData = record->decryptedData.first(record->decryptedData.size() - 1);
    }

    record->isDecrypted_ = true;
}

void Session::generateKeyMaterial(const int8_t sideIndex)
{
    if (!secrets_.isValid(ProtocolVersion::TLSv1_2))
    {
        return;
    }

    std::vector<uint8_t> keyBlock;
    if (secrets_.getSecret(SecretNode::MasterSecret).empty())
    {
        Secret masterSecret(48);
        if (handshake_.serverHello.extensions.has(tls::ExtensionCode::ExtendedMasterSecret))
        {
            auto sessionHash = handshakeHash_.final(cipherSuite_.getHnshDigestName());
            PRF(PMS_, "extended master secret", sessionHash, {}, masterSecret);
        }
        else
        {
            PRF(PMS_, "master secret", handshake_.clientHello.random, handshake_.serverHello.random, masterSecret);
        }
        secrets_.setSecret(SecretNode::MasterSecret, masterSecret);
    }

    if (debugKeys_)
    {
        utils::printHex(std::cout, secrets_.getSecret(SecretNode::MasterSecret), Colorize("MasterSecret"));
    }

    auto cipher = CipherSuiteManager::getInstance().fetchCipher(cipherSuite_.getCipherName());

    size_t keySize = crypto::GetKeyLength(cipher);
    size_t ivSize = crypto::GetIVLengthWithinKeyBlock(cipher);

    if (cipherSuite_.isAEAD())
    {
        keyBlock.resize(keySize * 2 + ivSize * 2);
        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", handshake_.serverHello.random,
            handshake_.clientHello.random, keyBlock);

        utils::MemoryViewer viewer(keyBlock);
        auto clientWriteKey = viewer.view(keySize);
        auto serverWriteKey = viewer.view(keySize);
        auto clientIV = viewer.view(ivSize);
        auto serverIV = viewer.view(ivSize);

        if (debugKeys_)
        {
            utils::printHex(std::cout, clientWriteKey, Colorize("Client Write key"));
            utils::printHex(std::cout, clientIV, Colorize("Client IV"));
            utils::printHex(std::cout, serverWriteKey, Colorize("Server Write key"));
            utils::printHex(std::cout, serverIV, Colorize("Server IV"));
        }

        if (sideIndex == 0)
        {
            clientToServer_.init(cipherSuite_, clientWriteKey, clientIV);
            canDecrypt_ |= 1;
        }
        else
        {
            serverToClient_.init(cipherSuite_, serverWriteKey, serverIV);
            canDecrypt_ |= 2;
        }
    }
    else
    {
        auto md = CipherSuiteManager::getInstance().fetchDigest(cipherSuite_.getDigestName());
        auto macSize = EVP_MD_get_size(md);

        keyBlock.resize(macSize * 2 + keySize * 2 + ivSize * 2);

        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", handshake_.serverHello.random,
            handshake_.clientHello.random, keyBlock);

        utils::MemoryViewer viewer(keyBlock);
        auto clientMacKey = viewer.view(macSize);
        auto serverMacKey = viewer.view(macSize);
        auto clientWriteKey = viewer.view(keySize);
        auto serverWriteKey = viewer.view(keySize);
        auto clientIV = viewer.view(ivSize);
        auto serverIV = viewer.view(ivSize);

        if (debugKeys_)
        {
            utils::printHex(std::cout, clientMacKey, Colorize("Client MAC key"));
            utils::printHex(std::cout, clientWriteKey, Colorize("Client Write key"));
            utils::printHex(std::cout, clientIV, Colorize("Client IV"));
            utils::printHex(std::cout, serverMacKey, Colorize("Server MAC key"));
            utils::printHex(std::cout, serverWriteKey, Colorize("Server Write key"));
            utils::printHex(std::cout, serverIV, Colorize("Server IV"));
        }

        if (sideIndex == 0)
        {
            clientToServer_.init(cipherSuite_, clientWriteKey, clientIV, clientMacKey);
            canDecrypt_ |= 1;
        }
        else
        {
            serverToClient_.init(cipherSuite_, serverWriteKey, serverIV, serverMacKey);
            canDecrypt_ |= 2;
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

    const auto& digest = cipherSuite_.getHnshDigestName();
    const auto& shts = secrets_.getSecret(SecretNode::ServerHandshakeTrafficSecret);

    auto serverHandshakeWriteKey = hkdfExpandLabel(digest, shts, "key", {}, keySize);
    auto serverHandshakeIV = hkdfExpandLabel(digest, shts, "iv", {}, 12);

    const auto& chts = secrets_.getSecret(SecretNode::ClientHandshakeTrafficSecret);

    auto clientHandshakeWriteKey = hkdfExpandLabel(digest, chts, "key", {}, keySize);
    auto clientHandshakeIV = hkdfExpandLabel(digest, chts, "iv", {}, 12);

    if (debugKeys_)
    {
        utils::printHex(std::cout, serverHandshakeWriteKey, Colorize("Server Handshake Write key"));
        utils::printHex(std::cout, serverHandshakeIV, Colorize("Server Handshake IV"));
        utils::printHex(std::cout, clientHandshakeWriteKey, Colorize("Client Handshake Write key"));
        utils::printHex(std::cout, clientHandshakeIV, Colorize("Client Handshake IV"));
    }

    clientToServer_.init(cipherSuite_, clientHandshakeWriteKey, clientHandshakeIV);
    serverToClient_.init(cipherSuite_, serverHandshakeWriteKey, serverHandshakeIV);

    canDecrypt_ |= 3;
}

void Session::PRF(const Secret& secret, std::string_view usage, cpp::span<const uint8_t> rnd1,
                  cpp::span<const uint8_t> rnd2, cpp::span<uint8_t> out)
{
    casket::ThrowIfFalse(version_ <= tls::ProtocolVersion::TLSv1_2, "Invalid TLS version");

    if (version_ == tls::ProtocolVersion::TLSv1_2)
    {
        auto digest = cipherSuite_.getHnshDigestName();
        if (digest == "MD5-SHA1")
        {
            digest = cipherSuite_.getDigestName();
        }
        tls1Prf(digest, secret, usage, rnd1, rnd2, out);
    }
    else if (version_ >= tls::ProtocolVersion::TLSv1_0)
    {
        auto digest = cipherSuite_.getHnshDigestName();
        tls1Prf(digest, secret, usage, rnd1, rnd2, out);
    }
    else
    {
        ssl3Prf(secret, rnd1, rnd2, out);
    }
}

const ProtocolVersion& Session::getVersion() const noexcept
{
    return version_;
}

const CipherSuite& Session::getCipherSuite() const noexcept
{
    return cipherSuite_;
}

void Session::setSecrets(SecretNode secrets)
{
    secrets_ = std::move(secrets);
}

const Secret& Session::getSecret(const SecretNode::Type type) const
{
    return secrets_.getSecret(type);
}

void Session::setPremasterSecret(std::vector<std::uint8_t> pms)
{
    PMS_ = std::move(pms);
}

void Session::setServerInfo(const ServerInfo& serverInfo)
{
    serverInfo_.setHostname(serverInfo.getHostname());
    serverInfo_.setIPAddress(serverInfo.getIPAddress());
    serverInfo_.setServerKey(serverInfo.getServerKey());
}

const ServerInfo& Session::getServerInfo() const noexcept
{
    return serverInfo_;
}

void Session::processClientHello(const std::int8_t sideIndex, cpp::span<const uint8_t> message)
{
    casket::ThrowIfFalse(sideIndex == 0, "Incorrect side index");
    handshake_.clientHello.deserialize(message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    handshakeHash_.update(message);

    version_ = handshake_.clientHello.legacyVersion;

    for (const auto& handler : *processor_)
    {
        handler->handleClientHello(handshake_.clientHello, this);
    }
}

void Session::processServerHello(const std::int8_t sideIndex, cpp::span<const uint8_t> message)
{
    casket::ThrowIfFalse(sideIndex == 1, "Incorrect side index");
    handshake_.serverHello.deserialize(message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    handshakeHash_.update(message);

    auto& serverHello = handshake_.serverHello;

    auto foundCipher = CipherSuiteManager::getInstance().getCipherSuiteById(serverHello.cipherSuite);
    casket::ThrowIfFalse(foundCipher.has_value(), "Cipher suite not found");
    cipherSuite_ = foundCipher.value();

    if (serverHello.extensions.has(tls::ExtensionCode::SupportedVersions))
    {
        auto ext = serverHello.extensions.get<tls::SupportedVersions>();
        version_ = std::move(ext->versions()[0]);
    }

    if (version_ == tls::ProtocolVersion::TLSv1_3)
    {
        generateTLS13KeyMaterial();
    }
}

void Session::processCertificate(const std::int8_t sideIndex, cpp::span<const uint8_t> message)
{
    static const char* debugInfo = (sideIndex == 0 ? "Client Certificate" : "Server Certificate");
    utils::DataReader reader(debugInfo, message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    if (getVersion() == ProtocolVersion::TLSv1_3)
    {
        auto requestContext = reader.get_range<uint8_t>(1, 0, 255);

        // RFC 8446 4.4.2
        //    [...] in the case of server authentication, this field SHALL be
        //    zero length.
        casket::ThrowIfTrue(sideIndex == 1 && !requestContext.empty(),
                             "Server Certificate message must not contain a request context");

        const size_t certEntriesLength = reader.get_uint24_t();
        casket::ThrowIfTrue(reader.remaining_bytes() != certEntriesLength, "Certificate: Message malformed");

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
        casket::ThrowIfTrue(reader.remaining_bytes() != certsLength, "Certificate: Message malformed");

        while (reader.has_remaining())
        {
            /// Certificate
            reader.get_tls_length_value(3);
        }
    }

    reader.assert_done();

    handshakeHash_.update(message);
}

void Session::processSessionTicket(const std::int8_t sideIndex, cpp::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
    if (version_ == ProtocolVersion::TLSv1_3)
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
        exts.deserialize(tls::Side::Server, reader.get_span_remaining());

        // reader.assert_done();
    }
    else if (version_ == ProtocolVersion::TLSv1_2)
    {
        utils::DataReader reader("TLSv1.2 New Session Ticket", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        casket::ThrowIfTrue(reader.remaining_bytes() < 6, "Session ticket message too short to be valid");
        reader.get_uint32_t();
        reader.get_range<uint8_t>(2, 0, 65535);
        reader.assert_done();
    }
    /*else
    {
        throw std::runtime_error("NewSessionTicket can't be in TLS versions below 1.2");
    }*/
}

void Session::processEncryptedExtensions(const std::int8_t sideIndex, cpp::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
    handshake_.encryptedExtensions.deserialize(message.subspan((TLS_HANDSHAKE_HEADER_SIZE)));
}

void Session::processServerKeyExchange(const std::int8_t sideIndex, cpp::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("ServerKeyExchange", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    auto kex = cipherSuite_.getKeyExchName();

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

    auto auth = cipherSuite_.getAuthName();
    if (auth == SN_auth_rsa || auth == SN_auth_dss || auth == SN_auth_ecdsa)
    {
        if (version_ == ProtocolVersion::TLSv1_2)
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

    handshakeHash_.update(message);
}

void Session::processCertificateRequest(const std::int8_t sideIndex, cpp::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("Certificate Request", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    casket::ThrowIfTrue(reader.remaining_bytes() < 4, "Certificate_Req: Bad certificate request");

    const auto cert_type_codes = reader.get_range_vector<uint8_t>(1, 1, 255);
    const std::vector<uint8_t> algs = reader.get_range_vector<uint8_t>(2, 2, 65534);

    casket::ThrowIfTrue(algs.size() % 2 != 0, "Bad length for signature IDs in certificate request");

    const uint16_t purported_size = reader.get_uint16_t();

    casket::ThrowIfTrue(reader.remaining_bytes() != purported_size, "Inconsistent length in certificate request");

    while (reader.has_remaining())
    {
        std::vector<uint8_t> name_bits = reader.get_range_vector<uint8_t>(2, 0, 65535);
    }

    reader.assert_done();

    handshakeHash_.update(message);
}

void Session::processServerHelloDone(const std::int8_t sideIndex, cpp::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("Server Hello Done", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    reader.assert_done();

    handshakeHash_.update(message);
}

void Session::processCertificateVerify(const std::int8_t sideIndex, cpp::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("CertificateVerify", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    reader.get_uint16_t();
    reader.get_range<uint8_t>(2, 0, 65535);
    reader.assert_done();

    handshakeHash_.update(message);
}

void Session::processClientKeyExchange(const std::int8_t sideIndex, cpp::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 0, "Incorrect side index");

    /// @todo: serialize

    handshakeHash_.update(message);

    if (!getServerInfo().getServerKey())
    {
        return;
    }

    if (getCipherSuite().getKeyExchName() == SN_kx_rsa)
    {
        utils::DataReader reader("ClientKeyExchange", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        const std::vector<uint8_t> encryptedPreMaster = reader.get_range<uint8_t>(2, 0, 65535);
        reader.assert_done();

        crypto::KeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, getServerInfo().getServerKey(), nullptr));
        crypto::ThrowIfFalse(ctx != nullptr);

        crypto::ThrowIfFalse(0 < EVP_PKEY_decrypt_init(ctx));
        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_WITH_TLS_PADDING));

        OSSL_PARAM params[2];
        unsigned int value = version_.code();
        params[0] = OSSL_PARAM_construct_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, &value);
        params[1] = OSSL_PARAM_construct_end();

        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_params(ctx, params));

        size_t size{0};
        crypto::ThrowIfFalse(0 < EVP_PKEY_decrypt(ctx, nullptr, &size, message.data(), message.size()));

        std::vector<std::uint8_t> pms(size);
        crypto::ThrowIfFalse(
            0 < EVP_PKEY_decrypt(ctx, pms.data(), &size, encryptedPreMaster.data(), encryptedPreMaster.size()));
        pms.resize(size);

        setPremasterSecret(std::move(pms));
    }
}

void Session::processFinished(const std::int8_t sideIndex, cpp::span<const uint8_t> message)
{
    (void)message;

    if (version_ == tls::ProtocolVersion::TLSv1_3)
    {
        auto keySize = cipherSuite_.getKeyBits() / 8;

        if (sideIndex == 0)
        {
            const auto& digest = cipherSuite_.getHnshDigestName();
            const auto& secret = getSecret(SecretNode::ClientTrafficSecret);

            auto clientWriteKey = hkdfExpandLabel(digest, secret, "key", {}, keySize);
            auto clientIV = hkdfExpandLabel(digest, secret, "iv", {}, 12);

            clientToServer_.init(cipherSuite_, clientWriteKey, clientIV);

            if (debugKeys_)
            {
                utils::printHex(std::cout, clientWriteKey, Colorize("Client Write key"));
                utils::printHex(std::cout, clientIV, Colorize("Client IV"));
            }
        }
        else
        {
            const auto& digest = cipherSuite_.getHnshDigestName();
            const auto& secret = getSecret(SecretNode::ServerTrafficSecret);

            auto serverWriteKey = hkdfExpandLabel(digest, secret, "key", {}, keySize);
            auto serverIV = hkdfExpandLabel(digest, secret, "iv", {}, 12);

            serverToClient_.init(cipherSuite_, serverWriteKey, serverIV);

            if (debugKeys_)
            {
                utils::printHex(std::cout, serverWriteKey, Colorize("Server Write key"));
                utils::printHex(std::cout, serverIV, Colorize("Server IV"));
            }
        }
    }
}

void Session::processKeyUpdate(const std::int8_t sideIndex, cpp::span<const uint8_t> message)
{
    (void)message;

    std::vector<uint8_t> newsecret;
    std::vector<uint8_t> newkey;
    std::vector<uint8_t> newiv;

    const auto& digest = cipherSuite_.getHnshDigestName();
    auto md = CipherSuiteManager::getInstance().fetchDigest(digest);
    auto keySize = cipherSuite_.getKeyBits() / 8;

    if (sideIndex == 0)
    {
        const auto& secret = getSecret(SecretNode::ClientTrafficSecret);
        auto newsecret = hkdfExpandLabel(digest, secret, "traffic upd", {}, EVP_MD_get_size(md));
        newkey = hkdfExpandLabel(digest, newsecret, "key", {}, keySize);
        newiv = hkdfExpandLabel(digest, newsecret, "iv", {}, 12);

        clientToServer_.tls13UpdateKeys(newkey, newiv);
    }
    else
    {
        const auto& secret = getSecret(SecretNode::ServerTrafficSecret);
        auto newsecret = hkdfExpandLabel(digest, secret, "traffic upd", {}, EVP_MD_get_size(md));
        newkey = hkdfExpandLabel(digest, newsecret, "key", {}, keySize);
        newiv = hkdfExpandLabel(digest, newsecret, "iv", {}, 12);

        serverToClient_.tls13UpdateKeys(newkey, newiv);
    }
}

} // namespace snet::tls