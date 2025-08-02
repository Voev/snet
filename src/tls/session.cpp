#include <cassert>
#include <limits>
#include <memory>
#include <openssl/core_names.h>

#include <casket/utils/exception.hpp>
#include <casket/utils/hexlify.hpp>
#include <casket/log/color.hpp>
#include <casket/utils/string.hpp>

#include <snet/utils/print_hex.hpp>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/cipher_context.hpp>
#include <snet/crypto/hash_traits.hpp>
#include <snet/crypto/signature.hpp>
#include <snet/crypto/crypto_manager.hpp>
#include <snet/crypto/secure_array.hpp>

#include <snet/tls/session.hpp>
#include <snet/tls/record_layer.hpp>
#include <snet/tls/prf.hpp>
#include <snet/tls/server_info.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

inline std::string Colorize(std::string_view text, std::string_view color = casket::lRed)
{
    return casket::format("[{}{}{}]", color, text, casket::resetColor);
}

namespace snet::tls
{

Session::Session(RecordPool& recordPool)
    : recordPool_(recordPool)
    , hashCtx_(crypto::CreateHashCtx())
    , clientCipherCtx_(crypto::CreateCipherCtx())
    , serverCipherCtx_(crypto::CreateCipherCtx())
    , cipherSuite_(nullptr)
    , cipherState_(0)
    , canDecrypt_(0)
    , debugKeys_(0)
{
}

void Session::reset() noexcept
{
    ResetCipherCtx(clientCipherCtx_);
    ResetCipherCtx(serverCipherCtx_);
    ResetHashCtx(hashCtx_);
}

bool Session::getCipherState(const std::int8_t sideIndex) const noexcept
{
    return ((cipherState_ & 0x1) && sideIndex == 0) || ((cipherState_ & 0x2) && sideIndex == 1);
}

bool Session::canDecrypt(const std::int8_t sideIndex) const noexcept
{
    return ((canDecrypt_ & 0x1) && sideIndex == 0) || ((canDecrypt_ & 0x2) && sideIndex == 1);
}

size_t Session::processRecords(const int8_t sideIndex, nonstd::span<const uint8_t> input)
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
    nonstd::span<const uint8_t> data;

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

void Session::decrypt(const std::int8_t sideIndex, Record* record)
{
    auto input = record->getData();
    auto encryptThenMAC = handshake_.serverHello.extensions.has(ExtensionCode::EncryptThenMac);
    auto tagLength = CipherSuiteManager::getInstance().getTagLengthByID(CipherSuiteGetID(cipherSuite_));

    if (version_ == ProtocolVersion::TLSv1_3)
    {
        if (sideIndex == 0)
        {
            record->decryptedData = RecordLayer::tls13Decrypt(
                clientCipherCtx_, record->getType(), seqnum_.getClientSequence(), clientEncKey_, clientIV_,
                input.subspan(TLS_HEADER_SIZE), record->decryptedBuffer, tagLength);
        }
        else
        {
            record->decryptedData = RecordLayer::tls13Decrypt(
                serverCipherCtx_, record->getType(), seqnum_.getServerSequence(), serverEncKey_, serverIV_,
                input.subspan(TLS_HEADER_SIZE), record->decryptedBuffer, tagLength);
        }

        uint8_t lastByte = record->decryptedData.back();
        casket::ThrowIfTrue(lastByte < 20 || lastByte > 23, "TLSv1.3 record type had unexpected value '{}'", lastByte);

        record->type = static_cast<RecordType>(lastByte);
        record->decryptedData = record->decryptedData.first(record->decryptedData.size() - 1);
    }
    else
    {
        if (sideIndex == 0)
        {
            record->decryptedData = RecordLayer::tls1Decrypt(
                clientCipherCtx_, hmacCtx_, hashCtx_, hmacHashAlg_, record->getType(), version_,
                seqnum_.getClientSequence(), clientEncKey_, clientMacKey_, clientIV_, input.subspan(TLS_HEADER_SIZE),
                record->decryptedBuffer, tagLength, encryptThenMAC, CipherSuiteIsAEAD(cipherSuite_));
        }
        else
        {
            record->decryptedData = RecordLayer::tls1Decrypt(
                serverCipherCtx_, hmacCtx_, hashCtx_, hmacHashAlg_, record->getType(), version_,
                seqnum_.getServerSequence(), serverEncKey_, serverMacKey_, serverIV_, input.subspan(TLS_HEADER_SIZE),
                record->decryptedBuffer, tagLength, encryptThenMAC, CipherSuiteIsAEAD(cipherSuite_));
        }
    }

    if (sideIndex == 0)
    {
        seqnum_.acceptClientSequence();
    }
    else
    {
        seqnum_.acceptServerSequence();
    }

    record->isDecrypted_ = true;
}

void Session::generateKeyMaterial(const int8_t sideIndex)
{
    if (!secrets_.isValid(ProtocolVersion::TLSv1_2))
    {
        return;
    }

    if (secrets_.getSecret(SecretNode::MasterSecret).empty())
    {
        Secret masterSecret(48);
        if (handshake_.serverHello.extensions.has(tls::ExtensionCode::ExtendedMasterSecret))
        {
            std::array<uint8_t, EVP_MAX_MD_SIZE> digest;
            const auto sessionHash =
                handshakeHash_.final(hashCtx_, CipherSuiteGetHandshakeDigest(cipherSuite_), digest);

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

    if (!cipherAlg_)
    {
        /// NULL cipher algorithm in cipher suite
        return;
    }

    size_t keySize = crypto::GetKeyLength(cipherAlg_);
    size_t ivSize = crypto::GetIVLengthWithinKeyBlock(cipherAlg_);

    if (CipherSuiteIsAEAD(cipherSuite_))
    {
        crypto::SecureArray<uint8_t, (EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH) * 2> keyBlockBuffer;
        size_t keyBlockSize = (keySize + ivSize) * 2;

        auto keyBlock = nonstd::span(keyBlockBuffer.data(), keyBlockSize);

        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", handshake_.serverHello.random,
            handshake_.clientHello.random, keyBlock);

        utils::DataReader reader("Key block (for AEAD)", keyBlock);

        clientEncKey_ = reader.get_fixed<uint8_t>(keySize);
        serverEncKey_ = reader.get_fixed<uint8_t>(keySize);
        clientIV_ = reader.get_fixed<uint8_t>(ivSize);
        serverIV_ = reader.get_fixed<uint8_t>(ivSize);

        reader.assert_done();

        if (debugKeys_)
        {
            utils::printHex(std::cout, clientEncKey_, Colorize("Client Write key"));
            utils::printHex(std::cout, clientIV_, Colorize("Client IV"));
            utils::printHex(std::cout, serverEncKey_, Colorize("Server Write key"));
            utils::printHex(std::cout, serverIV_, Colorize("Server IV"));
        }

        if (sideIndex == 0)
        {
            RecordLayer::init(clientCipherCtx_, cipherAlg_);
            canDecrypt_ |= 1;
        }
        else
        {
            RecordLayer::init(serverCipherCtx_, cipherAlg_);
            canDecrypt_ |= 2;
        }
    }
    else
    {
        auto macSize = EVP_MD_get_size(hmacHashAlg_);

        crypto::SecureArray<uint8_t, (EVP_MAX_MD_SIZE + EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH) * 2> keyBlockBuffer;
        size_t keyBlockSize = (macSize + keySize + ivSize) * 2;

        auto keyBlock = nonstd::span(keyBlockBuffer.data(), keyBlockSize);

        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", handshake_.serverHello.random,
            handshake_.clientHello.random, keyBlock);

        utils::DataReader reader("Key block (with MAC key)", keyBlock);

        clientMacKey_ = reader.get_fixed<uint8_t>(macSize);
        serverMacKey_ = reader.get_fixed<uint8_t>(macSize);
        clientEncKey_ = reader.get_fixed<uint8_t>(keySize);
        serverEncKey_ = reader.get_fixed<uint8_t>(keySize);
        clientIV_ = reader.get_fixed<uint8_t>(ivSize);
        serverIV_ = reader.get_fixed<uint8_t>(ivSize);

        reader.assert_done();

        if (debugKeys_)
        {
            utils::printHex(std::cout, clientMacKey_, Colorize("Client MAC key"));
            utils::printHex(std::cout, clientEncKey_, Colorize("Client Write key"));
            utils::printHex(std::cout, clientIV_, Colorize("Client IV"));
            utils::printHex(std::cout, serverMacKey_, Colorize("Server MAC key"));
            utils::printHex(std::cout, serverEncKey_, Colorize("Server Write key"));
            utils::printHex(std::cout, serverIV_, Colorize("Server IV"));
        }

        if (sideIndex == 0)
        {
            RecordLayer::init(clientCipherCtx_, cipherAlg_, clientEncKey_, clientIV_);
            canDecrypt_ |= 1;
        }
        else
        {
            RecordLayer::init(serverCipherCtx_, cipherAlg_, serverEncKey_, serverIV_);
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

    auto keySize = CipherSuiteGetKeySize(cipherSuite_);

    const auto& digest = CipherSuiteGetHandshakeDigest(cipherSuite_);
    const auto digestName = EVP_MD_name(digest);
    const auto& shts = secrets_.getSecret(SecretNode::ServerHandshakeTrafficSecret);

    serverEncKey_.resize(keySize);
    serverIV_.resize(12);

    DeriveKey(digestName, shts, serverEncKey_);
    DeriveIV(digestName, shts, serverIV_);

    const auto& chts = secrets_.getSecret(SecretNode::ClientHandshakeTrafficSecret);

    clientEncKey_.resize(keySize);
    clientIV_.resize(12);

    DeriveKey(digestName, chts, clientEncKey_);
    DeriveIV(digestName, chts, clientIV_);

    if (debugKeys_)
    {
        utils::printHex(std::cout, serverEncKey_, Colorize("Server Handshake Write key"));
        utils::printHex(std::cout, serverIV_, Colorize("Server Handshake IV"));
        utils::printHex(std::cout, clientEncKey_, Colorize("Client Handshake Write key"));
        utils::printHex(std::cout, clientIV_, Colorize("Client Handshake IV"));
    }

    RecordLayer::init(clientCipherCtx_, cipherAlg_);
    RecordLayer::init(serverCipherCtx_, cipherAlg_);

    canDecrypt_ |= 3;
}

std::string_view Session::getHashAlgorithm() const
{
    assert(version_ <= ProtocolVersion::TLSv1_2);

    std::string_view digest = EVP_MD_name(CipherSuiteGetHandshakeDigest(cipherSuite_));
    if (version_ == ProtocolVersion::TLSv1_2 && digest == "MD5-SHA1")
    {
        return CipherSuiteGetHmacDigestName(cipherSuite_);
    }
    return digest;
}

void Session::PRF(const Secret& secret, std::string_view usage, nonstd::span<const uint8_t> rnd1,
                  nonstd::span<const uint8_t> rnd2, nonstd::span<uint8_t> out)
{
    casket::ThrowIfFalse(version_ <= tls::ProtocolVersion::TLSv1_2, "Invalid TLS version");

    if (version_ == tls::ProtocolVersion::SSLv3_0)
    {
        ssl3Prf(secret, rnd1, rnd2, out);
    }
    else
    {
        auto algorithm = getHashAlgorithm();
        tls1Prf(algorithm, secret, usage, rnd1, rnd2, out);
    }
}

const ProtocolVersion& Session::getVersion() const noexcept
{
    return version_;
}

void Session::setSecrets(SecretNode secrets)
{
    secrets_ = std::move(secrets);
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

void Session::processClientHello(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
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

void Session::processServerHello(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    casket::ThrowIfFalse(sideIndex == 1, "Incorrect side index");
    handshake_.serverHello.deserialize(message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    handshakeHash_.update(message);

    auto& serverHello = handshake_.serverHello;

    if (serverHello.extensions.has(tls::ExtensionCode::SupportedVersions))
    {
        auto ext = serverHello.extensions.get<tls::SupportedVersions>();
        version_ = std::move(ext->versions()[0]);
    }

    cipherSuite_ = CipherSuiteManager::getInstance().getCipherSuiteById(serverHello.cipherSuite);
    casket::ThrowIfFalse(cipherSuite_, "Cipher suite not found");

    fetchAlgorithms();

    if (version_ == tls::ProtocolVersion::TLSv1_3)
    {
        generateTLS13KeyMaterial();
    }
}

void Session::processCertificate(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    if (sideIndex == 0) {}
    else
    {
        handshake_.serverCertificate.deserialize(sideIndex, version_, message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        if (version_ == ProtocolVersion::TLSv1_3)
        {
            casket::ThrowIfFalse(handshake_.serverCertificate.getRequestContext().empty(),
                                 "Server Certificate message must not contain a request context");
        }
    }

    handshakeHash_.update(message);
}

void Session::processCertificateRequest(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("Certificate Request", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    casket::ThrowIfTrue(reader.remaining_bytes() < 4, "Certificate_Req: Bad certificate request");

    const auto cert_type_codes = reader.get_range<uint8_t>(1, 1, 255);
    const auto algs = reader.get_span<uint8_t>(2, 2, 65534);

    casket::ThrowIfTrue(algs.size() % 2 != 0, "Bad length for signature IDs in certificate request");

    const uint16_t purported_size = reader.get_uint16_t();

    casket::ThrowIfTrue(reader.remaining_bytes() != purported_size, "Inconsistent length in certificate request");

    while (reader.has_remaining())
    {
        auto name_bits = reader.get_span<uint8_t>(2, 0, 65535);
    }

    reader.assert_done();

    handshakeHash_.update(message);
}

void Session::processCertificateVerify(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("CertificateVerify", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    reader.get_uint16_t();
    reader.get_span<uint8_t>(2, 0, 65535);
    reader.assert_done();

    handshakeHash_.update(message);
}

void Session::processEncryptedExtensions(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
    handshake_.encryptedExtensions.deserialize(message.subspan((TLS_HANDSHAKE_HEADER_SIZE)));
    handshakeHash_.update(message);
}

void Session::processServerKeyExchange(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    handshake_.serverKeyExchange.deserialize(message, CipherSuiteGetKeyExchange(cipherSuite_),
                                             CipherSuiteGetAuth(cipherSuite_), version_);

    handshakeHash_.update(message);

    /// RFC 4492: section-5.4
    if (!handshake_.serverKeyExchange.getSignature().empty())
    {
        std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
        const Hash* hash;
        crypto::HashPtr fetchedHash;

        auto scheme = handshake_.serverKeyExchange.getScheme();
        if (scheme.isSet())
        {
            fetchedHash = crypto::CryptoManager::getInstance().fetchDigest(scheme.getHashAlgorithm());
            hash = fetchedHash.get();
        }
        else
        {
            hash = CipherSuiteGetHandshakeDigest(cipherSuite_);
        }

        crypto::InitHash(hashCtx_, hash);
        crypto::UpdateHash(hashCtx_, handshake_.clientHello.random);
        crypto::UpdateHash(hashCtx_, handshake_.serverHello.random);
        crypto::UpdateHash(hashCtx_, handshake_.serverKeyExchange.getParams());

        auto digest = crypto::FinalHash(hashCtx_, buffer);
        auto publicKey = X509_get0_pubkey(handshake_.serverCertificate.getCert());

        crypto::VerifyDigest(hashCtx_, hash, publicKey, digest, handshake_.serverKeyExchange.getSignature());
    }
}

void Session::processClientKeyExchange(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 0, "Incorrect side index");

    /// @todo: deserialize

    handshakeHash_.update(message);

    if (!getServerInfo().getServerKey())
    {
        return;
    }

    if (CipherSuiteGetKeyExchange(cipherSuite_) == NID_kx_rsa)
    {
        utils::DataReader reader("ClientKeyExchange", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        const auto encryptedPreMaster = reader.get_span<uint8_t>(2, 0, 65535);
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

void Session::processServerHelloDone(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("Server Hello Done", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    reader.assert_done();

    handshakeHash_.update(message);
}

void Session::processFinished(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    if (sideIndex == 0)
    {
        handshake_.clientFinished.deserialize(version_, message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    }
    else
    {
        handshake_.serverFinished.deserialize(version_, message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    }

    /// Check Finished data

    switch (version_.code())
    {
    case ProtocolVersion::TLSv1_3:
    {
        const auto& secret = (sideIndex == 0 ? secrets_.getSecret(SecretNode::ClientHandshakeTrafficSecret)
                                             : secrets_.getSecret(SecretNode::ServerHandshakeTrafficSecret));
        if (!secret.empty())
        {

            const auto& digest = CipherSuiteGetHandshakeDigest(cipherSuite_);
            const auto digestName = EVP_MD_name(digest);

            crypto::SecureArray<uint8_t, EVP_MAX_MD_SIZE> finishedKey;
            size_t keySize = EVP_MD_get_size(digest);

            DeriveFinishedKey(digestName, secret, {finishedKey.data(), keySize});

            crypto::KeyPtr hmacKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, finishedKey.data(), keySize));
            const auto& expect = (sideIndex == 0 ? handshake_.clientFinished.getVerifyData()
                                                 : handshake_.serverFinished.getVerifyData());

            std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
            std::array<uint8_t, EVP_MAX_MD_SIZE> actual;
            size_t length = actual.size();
            const auto transcriptHash = handshakeHash_.final(hashCtx_, digest, buffer);

            crypto::ThrowIfFalse(0 < EVP_DigestSignInit(hashCtx_, nullptr, digest, nullptr, hmacKey));
            crypto::ThrowIfFalse(0 < EVP_DigestSignUpdate(hashCtx_, transcriptHash.data(), transcriptHash.size()));
            crypto::ThrowIfFalse(0 < EVP_DigestSignFinal(hashCtx_, actual.data(), &length));

            casket::ThrowIfFalse(expect.size() == length && std::equal(expect.begin(), expect.end(), actual.begin()),
                                 "Bad Finished MAC");
        }
        break;
    }
    case ProtocolVersion::TLSv1_2:
    case ProtocolVersion::TLSv1_1:
    case ProtocolVersion::TLSv1_0:
    {
        if (!secrets_.getSecret(SecretNode::MasterSecret).empty())
        {
            std::string_view algorithm = getHashAlgorithm();
            auto fetchedAlg = crypto::CryptoManager::getInstance().fetchDigest(algorithm);

            std::array<uint8_t, EVP_MAX_MD_SIZE> digest;
            const auto transcriptHash = handshakeHash_.final(hashCtx_, fetchedAlg, digest);
            const auto& key = secrets_.getSecret(SecretNode::MasterSecret);
            const auto& expect = (sideIndex == 0 ? handshake_.clientFinished.getVerifyData()
                                                 : handshake_.serverFinished.getVerifyData());

            std::array<uint8_t, TLS1_FINISH_MAC_LENGTH> actual;
            tls1Prf(algorithm, key, (sideIndex == 0 ? "client finished" : "server finished"), transcriptHash, {},
                    actual);

            casket::ThrowIfFalse(expect.size() == actual.size() &&
                                     std::equal(expect.begin(), expect.end(), actual.begin()),
                                 "Bad Finished MAC");
        }
        break;
    }
    case ProtocolVersion::SSLv3_0:
        /// @todo: do it.
        break;
    }

    /// Update transcript hash

    if (version_ == ProtocolVersion::TLSv1_3)
    {
        handshakeHash_.update(message);
    }
    else
    {
        if (sideIndex == 0)
        {
            handshakeHash_.update(message);
        }
    }

    /// Generate key material

    if (version_ == tls::ProtocolVersion::TLSv1_3)
    {
        if (sideIndex == 0)
        {
            const auto& digest = CipherSuiteGetHandshakeDigest(cipherSuite_);
            const auto digestName = EVP_MD_name(digest);
            const auto& secret = secrets_.getSecret(SecretNode::ClientTrafficSecret);

            clientEncKey_.resize(CipherSuiteGetKeySize(cipherSuite_));
            clientIV_.resize(12);

            DeriveKey(digestName, secret, clientEncKey_);
            DeriveIV(digestName, secret, clientIV_);

            seqnum_.resetClientSequence();

            if (debugKeys_)
            {
                utils::printHex(std::cout, clientEncKey_, Colorize("Client Write key"));
                utils::printHex(std::cout, clientIV_, Colorize("Client IV"));
            }
        }
        else
        {
            std::string_view digestName = EVP_MD_name(CipherSuiteGetHandshakeDigest(cipherSuite_));
            const auto& secret = secrets_.getSecret(SecretNode::ServerTrafficSecret);

            serverEncKey_.resize(CipherSuiteGetKeySize(cipherSuite_));
            serverIV_.resize(12);

            DeriveKey(digestName, secret, serverEncKey_);
            DeriveIV(digestName, secret, serverIV_);

            seqnum_.resetServerSequence();

            if (debugKeys_)
            {
                utils::printHex(std::cout, serverEncKey_, Colorize("Server Write key"));
                utils::printHex(std::cout, serverIV_, Colorize("Server IV"));
            }
        }
    }
}

void Session::processSessionTicket(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
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
        reader.get_span<uint8_t>(2, 0, 65535);
        reader.assert_done();

        // RFC 5077: 3.3 (must be included in transcript hash)
        handshakeHash_.update(message);
    }
    else
    {
        handshakeHash_.update(message);
    }
}

void Session::processKeyUpdate(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    (void)message;

    const auto& digest = CipherSuiteGetHandshakeDigest(cipherSuite_);
    std::string_view digestName = EVP_MD_name(digest);

    if (sideIndex == 0)
    {
        UpdateTrafficSecret(digestName, secrets_.get(SecretNode::ClientTrafficSecret));

        clientEncKey_.resize(CipherSuiteGetKeySize(cipherSuite_));
        clientIV_.resize(12);

        DeriveKey(digestName, secrets_.get(SecretNode::ClientTrafficSecret), clientEncKey_);
        DeriveIV(digestName, secrets_.get(SecretNode::ClientTrafficSecret), clientIV_);

        seqnum_.resetClientSequence();
    }
    else
    {
        UpdateTrafficSecret(digestName, secrets_.get(SecretNode::ServerTrafficSecret));

        serverEncKey_.resize(CipherSuiteGetKeySize(cipherSuite_));
        serverIV_.resize(12);

        DeriveKey(digestName, secrets_.get(SecretNode::ServerTrafficSecret), serverEncKey_);
        DeriveIV(digestName, secrets_.get(SecretNode::ServerTrafficSecret), serverIV_);

        seqnum_.resetServerSequence();
    }
}

void Session::fetchAlgorithms()
{
    // Don't call for unknown protocol version and cipher suite
    assert(version_ != ProtocolVersion());
    assert(cipherSuite_ != nullptr);

    auto isAEAD = false;
    auto cipherName = CipherSuiteGetCipherName(cipherSuite_);
    if (!casket::iequals(cipherName, "UNDEF"))
    {
        cipherAlg_ = crypto::CryptoManager::getInstance().fetchCipher(cipherName);
        isAEAD = CipherIsAEAD(cipherAlg_);
    }

    if (!isAEAD) // TLSv1.3 uses only AEAD, so don't check for version
    {
        hmacHashAlg_ = crypto::CryptoManager::getInstance().fetchDigest(CipherSuiteGetHmacDigestName(cipherSuite_));

        if (version_ != ProtocolVersion::SSLv3_0)
        {
            OSSL_PARAM params[2];
            params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                         const_cast<char*>(crypto::GetHashName(hmacHashAlg_)), 0);
            params[1] = OSSL_PARAM_construct_end();

            auto mac = crypto::CryptoManager::getInstance().fetchMac("HMAC");

            hmacCtx_.reset(EVP_MAC_CTX_new(mac));
            crypto::ThrowIfTrue(hmacCtx_ == nullptr, "failed to create HMAC context");

            crypto::ThrowIfFalse(0 < EVP_MAC_CTX_set_params(hmacCtx_, params));
        }
    }
}

} // namespace snet::tls