#include <cassert>
#include <limits>
#include <memory>

#include <casket/utils/exception.hpp>
#include <casket/utils/hexlify.hpp>
#include <casket/log/color.hpp>
#include <casket/utils/string.hpp>

#include <snet/utils/print_hex.hpp>

#include <snet/crypto/asymm_key.hpp>
#include <snet/crypto/exception.hpp>
#include <snet/crypto/cert.hpp>
#include <snet/crypto/cipher_traits.hpp>
#include <snet/crypto/hash_traits.hpp>
#include <snet/crypto/hmac_traits.hpp>
#include <snet/crypto/signature.hpp>
#include <snet/crypto/crypto_manager.hpp>
#include <snet/crypto/secure_array.hpp>
#include <snet/crypto/prf.hpp>
#include <snet/crypto/rsa_asymm_key.hpp>

#include <snet/tls/session.hpp>
#include <snet/tls/record_layer.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

#include <openssl/evp.h>

using namespace snet::crypto;

inline std::string Colorize(std::string_view text, std::string_view color = casket::lRed)
{
    return casket::format("[{}{}{}]", color, text, casket::resetColor);
}

namespace snet::tls
{

Session::Session(RecordPool& recordPool)
    : recordPool_(recordPool)
    , hashCtx_(HashTraits::createContext())
    , hmacCtx_(HmacTraits::createContext())
    , clientCipherCtx_(CipherTraits::createContext())
    , serverCipherCtx_(CipherTraits::createContext())
    , cipherState_(0)
    , canDecrypt_(0)
    , monitor_(0)
    , debugKeys_(0)
{
}

void Session::reset() noexcept
{
    recordLayer_.reset();

    hmacHashAlg_ = nullptr;
    cipherAlg_ = nullptr;

    CipherTraits::resetContext(clientCipherCtx_);
    CipherTraits::resetContext(serverCipherCtx_);
    HashTraits::resetContext(hashCtx_);
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
        if (!readingRecord_)
        {
            if (input.size() < processedLength + TLS_HEADER_SIZE)
            {
                break;
            }

            readingRecord_ = recordPool_.acquire();
            if (!readingRecord_)
            {
                return processedLength;
            }

            readingRecord_->deserializeHeader(input.subspan(processedLength, TLS_HEADER_SIZE));
        }

        const size_t payloadProcessed = readingRecord_->initPayload(input.subspan(processedLength));
        processedLength += payloadProcessed;

        if (readingRecord_->isFullyAssembled() && processor_)
        {
            preprocessRecord(sideIndex, readingRecord_);

            for (const auto& handler : *processor_)
            {
                handler->handleRecord(sideIndex, this, readingRecord_);
            }

            postprocessRecord(sideIndex, readingRecord_);

            recordPool_.release(std::exchange(readingRecord_, nullptr));
        }
    }

    if (readingRecord_)
    {
        if (processedLength == 0)
        {
            recordPool_.release(std::exchange(readingRecord_, nullptr));
        }
        return 0;
    }

    return processedLength;
}

void Session::preprocessRecord(const std::int8_t sideIndex, Record* record)
{
    nonstd::span<const uint8_t> data;

    if (canDecrypt(sideIndex) && record->getType() != RecordType::ChangeCipherSpec)
    {
        decrypt(sideIndex, record);
        data = record->getPlaintext();
    }
    else
    {
        data = record->getCiphertext().subspan(TLS_HEADER_SIZE);
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

        record->deserializeHandshake(data, metaInfo_);

        switch (record->getHandshakeType())
        {
        case HandshakeType::ClientHelloCode:
        {
            casket::ThrowIfFalse(sideIndex == 0, "Incorrect side index");
            processClientHello(record->getHandshake<ClientHello>());
            std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            break;
        }
        case HandshakeType::ServerHelloCode:
        {
            casket::ThrowIfFalse(sideIndex == 1, "Incorrect side index");
            processServerHello(record->getHandshake<ServerHello>());
            std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            break;
        }
        case HandshakeType::EncryptedExtensionsCode:
        {
            casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
            processEncryptedExtensions(record->getHandshake<EncryptedExtensions>());
            std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            break;
        }
        case HandshakeType::ServerHelloDoneCode:
        {
            casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
            utils::DataReader reader("Server Hello Done", data.subspan(TLS_HANDSHAKE_HEADER_SIZE));
            reader.assert_done();
            std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            break;
        }
        case HandshakeType::ServerKeyExchangeCode:
        {
            casket::ThrowIfFalse(sideIndex == 1, "Incorrect side index");
            processServerKeyExchange(record->getHandshake<ServerKeyExchange>());
            std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            break;
        }
        case HandshakeType::ClientKeyExchangeCode:
        {
            processClientKeyExchange(sideIndex, data);
            std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            break;
        }
        case HandshakeType::CertificateCode:
        {
            processCertificate(sideIndex, record->getHandshake<Certificate>());
            std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            break;
        }
        case HandshakeType::CertificateRequestCode:
        {
            processCertificateRequest(sideIndex, record->getHandshake<CertificateRequest>());
            std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            break;
        }
        case HandshakeType::CertificateVerifyCode:
        {
            processCertificateVerify(sideIndex, record->getHandshake<CertificateVerify>());
            std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            break;
        }
        case HandshakeType::FinishedCode:
        {
            processFinished(sideIndex, record->getHandshake<Finished>());

            if (metaInfo_.version == ProtocolVersion::TLSv1_3 || sideIndex == 0)
            {
                std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            }
            break;
        }
        case HandshakeType::NewSessionTicketCode:
        {
            casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
            processNewSessionTicket(record->getHandshake<NewSessionTicket>());

            if (metaInfo_.version < ProtocolVersion::TLSv1_3)
            {
                // RFC 5077: 3.3 (must be included in transcript hash)
                std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            }
            break;
        }
        case HandshakeType::KeyUpdateCode:
        {
            processKeyUpdate(sideIndex, data);
            break;
        }
        case HandshakeType::HelloRequestCode:
        case HandshakeType::HelloVerifyRequestCode:
        case HandshakeType::EndOfEarlyDataCode:
        case HandshakeType::HelloRetryRequestCode:
        case HandshakeType::HandshakeCCSCode:
        default:
            /* Not implemented */
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

void Session::decrypt(const int8_t sideIndex, Record* record)
{
    if (sideIndex == 0)
    {
        recordLayer_.decrypt(clientCipherCtx_, hmacCtx_, hashCtx_, hmacHashAlg_, record, seqnum_.getClientSequence(),
                             keyInfo_.clientEncKey, keyInfo_.clientMacKey, keyInfo_.clientIV);
        seqnum_.acceptClientSequence();
    }
    else
    {
        recordLayer_.decrypt(serverCipherCtx_, hmacCtx_, hashCtx_, hmacHashAlg_, record, seqnum_.getServerSequence(),
                             keyInfo_.serverEncKey, keyInfo_.serverMacKey, keyInfo_.serverIV);
        seqnum_.acceptServerSequence();
    }
}

void Session::generateKeyMaterial(const int8_t sideIndex)
{
    if (!keyInfo_.isValid(ProtocolVersion::TLSv1_2))
    {
        return;
    }

    if (keyInfo_.masterSecret.empty())
    {
        ThrowIfTrue(PMS_.empty(), "Premaster secret not setted");
        keyInfo_.masterSecret.resize(TLS_MASTER_SECRET_SIZE);

        if (serverExtensions_.has(tls::ExtensionCode::ExtendedMasterSecret))
        {
            std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
            HashTraits::hashInit(hashCtx_, handshakeHashAlg_);
            HashTraits::hashUpdate(hashCtx_, handshakeBuffer_);
            auto transcriptHash = HashTraits::hashFinal(hashCtx_, buffer);

            PRF(PMS_, "extended master secret", transcriptHash, {}, keyInfo_.masterSecret);
        }
        else
        {
            PRF(PMS_, "master secret", clientRandom_, serverRandom_, keyInfo_.masterSecret);
        }
    }

    if (debugKeys_)
    {
        utils::printHex(std::cout, keyInfo_.masterSecret, Colorize("MasterSecret"));
    }

    if (!cipherAlg_)
    {
        /// NULL cipher algorithm in cipher suite
        return;
    }

    size_t keySize = CipherTraits::getKeyLength(cipherAlg_);
    size_t ivSize = CipherTraits::getIVLengthWithinKeyBlock(cipherAlg_);

    if (CipherTraits::isAEAD(cipherAlg_))
    {
        crypto::SecureArray<uint8_t, (TLS_MAX_KEY_LENGTH + TLS_MAX_IV_LENGTH) * 2> keyBlockBuffer;
        size_t keyBlockSize = (keySize + ivSize) * 2;

        auto keyBlock = nonstd::span(keyBlockBuffer.data(), keyBlockSize);

        PRF(keyInfo_.masterSecret, "key expansion", serverRandom_, clientRandom_, keyBlock);

        utils::DataReader reader("Key block (for AEAD)", keyBlock);

        keyInfo_.clientEncKey.assign(reader.get_span_fixed(keySize));
        keyInfo_.serverEncKey.assign(reader.get_span_fixed(keySize));
        keyInfo_.clientIV.assign(reader.get_span_fixed(ivSize));
        keyInfo_.serverIV.assign(reader.get_span_fixed(ivSize));

        reader.assert_done();

        if (debugKeys_)
        {
            utils::printHex(std::cout, keyInfo_.clientEncKey, Colorize("Client Write key"));
            utils::printHex(std::cout, keyInfo_.clientIV, Colorize("Client IV"));
            utils::printHex(std::cout, keyInfo_.serverEncKey, Colorize("Server Write key"));
            utils::printHex(std::cout, keyInfo_.serverIV, Colorize("Server IV"));
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
        auto macSize = HashTraits::getSize(hmacHashAlg_);

        crypto::SecureArray<uint8_t, (TLS_MAX_MAC_LENGTH + TLS_MAX_KEY_LENGTH + TLS_MAX_IV_LENGTH) * 2> keyBlockBuffer;
        size_t keyBlockSize = (macSize + keySize + ivSize) * 2;

        auto keyBlock = nonstd::span(keyBlockBuffer.data(), keyBlockSize);

        PRF(keyInfo_.masterSecret, "key expansion", serverRandom_, clientRandom_, keyBlock);

        utils::DataReader reader("Key block (with MAC key)", keyBlock);

        keyInfo_.clientMacKey.assign(reader.get_span_fixed(macSize));
        keyInfo_.serverMacKey.assign(reader.get_span_fixed(macSize));
        keyInfo_.clientEncKey.assign(reader.get_span_fixed(keySize));
        keyInfo_.serverEncKey.assign(reader.get_span_fixed(keySize));
        keyInfo_.clientIV.assign(reader.get_span_fixed(ivSize));
        keyInfo_.serverIV.assign(reader.get_span_fixed(ivSize));

        reader.assert_done();

        if (debugKeys_)
        {
            utils::printHex(std::cout, keyInfo_.clientMacKey, Colorize("Client MAC key"));
            utils::printHex(std::cout, keyInfo_.clientEncKey, Colorize("Client Write key"));
            utils::printHex(std::cout, keyInfo_.clientIV, Colorize("Client IV"));
            utils::printHex(std::cout, keyInfo_.serverMacKey, Colorize("Server MAC key"));
            utils::printHex(std::cout, keyInfo_.serverEncKey, Colorize("Server Write key"));
            utils::printHex(std::cout, keyInfo_.serverIV, Colorize("Server IV"));
        }

        if (sideIndex == 0)
        {
            RecordLayer::init(clientCipherCtx_, cipherAlg_, keyInfo_.clientEncKey, keyInfo_.clientIV);
            canDecrypt_ |= 1;
        }
        else
        {
            RecordLayer::init(serverCipherCtx_, cipherAlg_, keyInfo_.serverEncKey, keyInfo_.serverIV);
            canDecrypt_ |= 2;
        }
    }
}

void Session::generateTLS13KeyMaterial()
{
    if (!keyInfo_.isValid(ProtocolVersion::TLSv1_3))
    {
        return;
    }

    const auto digestName = CipherSuiteGetHandshakeDigestName(metaInfo_.cipherSuite);

    crypto::DeriveKey(digestName, keyInfo_.clientHndTrafficSecret, keyInfo_.clientEncKey);
    crypto::DeriveKey(digestName, keyInfo_.serverHndTrafficSecret, keyInfo_.serverEncKey);

    crypto::DeriveIV(digestName, keyInfo_.clientHndTrafficSecret, keyInfo_.clientIV);
    crypto::DeriveIV(digestName, keyInfo_.serverHndTrafficSecret, keyInfo_.serverIV);

    if (debugKeys_)
    {
        utils::printHex(std::cout, keyInfo_.serverEncKey, Colorize("Server Handshake Write key"));
        utils::printHex(std::cout, keyInfo_.serverIV, Colorize("Server Handshake IV"));
        utils::printHex(std::cout, keyInfo_.clientEncKey, Colorize("Client Handshake Write key"));
        utils::printHex(std::cout, keyInfo_.clientIV, Colorize("Client Handshake IV"));
    }

    RecordLayer::init(clientCipherCtx_, cipherAlg_);
    RecordLayer::init(serverCipherCtx_, cipherAlg_);

    canDecrypt_ |= 3;
}

std::string_view Session::getHashAlgorithm() const
{
    std::string_view digest = HashTraits::getName(CipherSuiteGetHandshakeDigest(metaInfo_.cipherSuite));
    if (metaInfo_.version == ProtocolVersion::TLSv1_2 && digest == "MD5-SHA1")
    {
        return CipherSuiteGetHmacDigestName(metaInfo_.cipherSuite);
    }
    return digest;
}

void Session::PRF(nonstd::span<const uint8_t> secret, std::string_view usage, nonstd::span<const uint8_t> rnd1,
                  nonstd::span<const uint8_t> rnd2, nonstd::span<uint8_t> out)
{
    casket::ThrowIfFalse(metaInfo_.version <= tls::ProtocolVersion::TLSv1_2, "Invalid TLS version");

    if (metaInfo_.version == tls::ProtocolVersion::SSLv3_0)
    {
        crypto::ssl3Prf(secret, rnd1, rnd2, out);
    }
    else
    {
        auto algorithm = getHashAlgorithm();
        crypto::tls1Prf(algorithm, secret, usage, rnd1, rnd2, out);
    }
}

const ProtocolVersion& Session::getVersion() const noexcept
{
    return metaInfo_.version;
}

void Session::setSecrets(const SecretNode* secrets)
{
    keyInfo_.masterSecret.assign(secrets->masterSecret);
    keyInfo_.clientEarlyTrafficSecret.assign(secrets->clientEarlyTrafficSecret);
    keyInfo_.clientHndTrafficSecret.assign(secrets->clientHndTrafficSecret);
    keyInfo_.clientAppTrafficSecret.assign(secrets->clientAppTrafficSecret);
    keyInfo_.serverHndTrafficSecret.assign(secrets->serverHndTrafficSecret);
    keyInfo_.serverAppTrafficSecret.assign(secrets->serverAppTrafficSecret);
}

void Session::setPremasterSecret(std::vector<std::uint8_t> pms)
{
    PMS_ = std::move(pms);
}

void Session::setServerKey(Key* key)
{
    serverKey_ = crypto::AsymmKey::shallowCopy(key);
}

void Session::processClientHello(const ClientHello& clientHello)
{
    metaInfo_.version = clientHello.version;

    assert(clientHello.random.size() == TLS_RANDOM_SIZE);
    std::copy_n(clientHello.random.data(), TLS_RANDOM_SIZE, clientRandom_.data());

    if (metaInfo_.version != ProtocolVersion::SSLv3_0)
    {
        clientExtensions_.deserialize(Side::Client, clientHello.extensions, HandshakeType::ClientHelloCode);
    }

    if (processor_)
    {
        for (const auto& handler : *processor_)
        {
            handler->handleClientHello(clientHello, this);
        }
    }
}

void Session::processServerHello(const ServerHello& serverHello)
{
    assert(serverHello.random.size() == TLS_RANDOM_SIZE);
    std::copy_n(serverHello.random.data(), TLS_RANDOM_SIZE, serverRandom_.data());

    if (!serverHello.extensions.empty())
    {
        serverExtensions_.deserialize(Side::Server, serverHello.extensions, HandshakeType::ServerHelloCode);

        if (serverExtensions_.has(tls::ExtensionCode::SupportedVersions))
        {
            auto ext = serverExtensions_.get<tls::SupportedVersions>();
            metaInfo_.version = std::move(ext->versions()[0]);
        }

        if (serverExtensions_.has(tls::ExtensionCode::EncryptThenMac))
        {
            recordLayer_.enableEncryptThenMAC();
        }
    }

    metaInfo_.cipherSuite = CipherSuiteManager::getInstance().getCipherSuiteById(serverHello.cipherSuite);
    casket::ThrowIfFalse(metaInfo_.cipherSuite, "Cipher suite not found");

    if (!monitor_)
    {
        recordLayer_.setVersion(metaInfo_.version);
        fetchAlgorithms();

        if (metaInfo_.version == tls::ProtocolVersion::TLSv1_3)
        {
            generateTLS13KeyMaterial();
        }
    }
}

void Session::processCertificate(const int8_t sideIndex, const Certificate& certificate)
{
    if (std::holds_alternative<TLSv13Certificate>(certificate.message))
    {
        const auto& message = std::get<TLSv13Certificate>(certificate.message);
        if (sideIndex == 0)
        {
            clientCert_ = crypto::Cert::fromBuffer(message.entryList[0].certData);
        }
        else
        {
            serverCert_ = crypto::Cert::fromBuffer(message.entryList[0].certData);
        }
    }
    else if (std::holds_alternative<TLSv1Certificate>(certificate.message))
    {
        const auto& message = std::get<TLSv1Certificate>(certificate.message);
        if (sideIndex == 0)
        {
            clientCert_ = crypto::Cert::fromBuffer(message.entryList[0].certData);
        }
        else
        {
            serverCert_ = crypto::Cert::fromBuffer(message.entryList[0].certData);
        }
    }

    /// @todo verify certificate chain
}

void Session::processCertificateRequest(const std::int8_t sideIndex, const CertificateRequest& certRequest)
{
    /// @todo: do it.
    (void)sideIndex;
    (void)certRequest;
}

static const size_t TLS13_TBS_START_SIZE = 64;
static const size_t TLS13_TBS_LABEL_SIZE = 34;

/// To be signed message prefix for TLSv1.3
static const std::array<uint8_t, TLS13_TBS_START_SIZE> startTbs = {
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20};
/// ASCII: "TLS 1.3, server CertificateVerify" with 0x00
static const std::array<uint8_t, TLS13_TBS_LABEL_SIZE> serverContext = {
    0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33, 0x2c, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x43,
    0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x00};
/// ASCII: "TLS 1.3, client CertificateVerify" with 0x00
static const std::array<uint8_t, TLS13_TBS_LABEL_SIZE> clientContext = {
    0x54, 0x4c, 0x53, 0x20, 0x31, 0x2e, 0x33, 0x2c, 0x20, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x20, 0x43,
    0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x56, 0x65, 0x72, 0x69, 0x66, 0x79, 0x00};

static void VerifyMessage(HashCtx* ctx, const SignatureScheme& scheme, const Hash* algorithm, Key* publicKey,
                          nonstd::span<const uint8_t> signature, nonstd::span<const uint8_t> tbs)
{
    KeyCtx* keyCtx{nullptr};

    HashTraits::resetContext(ctx);

    Signature::verifyInit(ctx, algorithm, publicKey, &keyCtx);

    if (scheme.getKeyAlgorithm() == EVP_PKEY_RSA_PSS)
    {
        RsaAsymmKey::setPssSettings(keyCtx);
    }

    Signature::verify(ctx, signature, tbs);
}

void Session::processCertificateVerify(const int8_t sideIndex, const CertificateVerify& certVerify)
{
    KeyPtr publicKey{nullptr};
    HashAlg hash{nullptr};

    if (metaInfo_.version == ProtocolVersion::TLSv1_3)
    {
        auto hashName = certVerify.scheme.getHashAlgorithm();
        if (!casket::equals(hashName, "UNDEF"))
        {
            hash = CryptoManager::getInstance().fetchDigest(hashName);
        }

        std::vector<uint8_t> tbs;
        tbs.reserve(TLS13_TBS_START_SIZE + TLS13_TBS_LABEL_SIZE + EVP_MAX_MD_SIZE);
        tbs.insert(tbs.end(), std::begin(startTbs), std::end(startTbs));

        if (sideIndex == 0)
        {
            publicKey = Cert::publicKey(clientCert_);
            tbs.insert(tbs.end(), std::begin(clientContext), std::end(clientContext));
        }
        else
        {
            publicKey = Cert::publicKey(serverCert_);
            tbs.insert(tbs.end(), std::begin(serverContext), std::end(serverContext));
        }

        std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
        HashTraits::hashInit(hashCtx_, handshakeHashAlg_);
        HashTraits::hashUpdate(hashCtx_, handshakeBuffer_);
        auto transcriptHash = HashTraits::hashFinal(hashCtx_, buffer);

        tbs.insert(tbs.end(), transcriptHash.begin(), transcriptHash.end());

        VerifyMessage(hashCtx_, certVerify.scheme, hash, publicKey, certVerify.signature, tbs);
    }
    else if (metaInfo_.version <= ProtocolVersion::TLSv1_2)
    {
        casket::ThrowIfFalse(sideIndex == 0, "CertificateVerify: invalid side index");
        auto publicKey = Cert::publicKey(clientCert_);

        if (certVerify.scheme.isSet())
        {
            auto hashName = certVerify.scheme.getHashAlgorithm();
            if (!casket::equals(hashName, "UNDEF"))
            {
                hash = CryptoManager::getInstance().fetchDigest(hashName);
            }
        }
        else if (metaInfo_.version < ProtocolVersion::TLSv1_2 && AsymmKey::isAlgorithm(publicKey, "RSA"))
        {
            hash = CryptoManager::getInstance().fetchDigest(SN_md5_sha1);
        }
        else
        {
            hash = CryptoManager::getInstance().fetchDigest(CipherSuiteGetHmacDigestName(metaInfo_.cipherSuite));
        }

        VerifyMessage(hashCtx_, certVerify.scheme, hash, publicKey, certVerify.signature, handshakeBuffer_);
    }
}

void Session::processEncryptedExtensions(const EncryptedExtensions& encryptedExtensions)
{
    serverEncExtensions_.deserialize(Side::Server, encryptedExtensions.extensions,
                                     HandshakeType::EncryptedExtensionsCode);
}

void Session::processServerKeyExchange(const ServerKeyExchange& keyExchange)
{
    /// RFC 4492: section-5.4
    if (!keyExchange.signature.empty())
    {
        crypto::HashAlg hash;

        auto publicKey = Cert::publicKey(serverCert_);
        auto scheme = keyExchange.scheme;

        /// version == TLS1.2
        if (scheme.isSet())
        {
            /// In the case of Ed25519 and Ed448 hash algorithm is built into the signature algorithm.
            if (!casket::equals(scheme.getHashAlgorithm(), "UNDEF"))
            {
                hash = CryptoManager::getInstance().fetchDigest(scheme.getHashAlgorithm());
            }
        }
        else if (metaInfo_.version < ProtocolVersion::TLSv1_2 && AsymmKey::isAlgorithm(publicKey, "RSA"))
        {
            hash = CryptoManager::getInstance().fetchDigest(SN_md5_sha1);
        }
        else
        {
            hash = CryptoManager::getInstance().fetchDigest(CipherSuiteGetHmacDigestName(metaInfo_.cipherSuite));
        }

        std::vector<uint8_t> tbs;
        tbs.reserve(2 * TLS_RANDOM_SIZE + keyExchange.data.size());

        tbs.insert(tbs.end(), clientRandom_.begin(), clientRandom_.end());
        tbs.insert(tbs.end(), serverRandom_.begin(), serverRandom_.end());
        tbs.insert(tbs.end(), keyExchange.data.begin(), keyExchange.data.end());

        VerifyMessage(hashCtx_, keyExchange.scheme, hash, publicKey, keyExchange.signature, tbs);
    }
}

void Session::processClientKeyExchange(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 0, "Incorrect side index");

    /// @todo: deserialize

    (void)message;

    if (!serverKey_)
    {
        return;
    }

    /*if (CipherSuiteGetKeyExchange(metaInfo_.cipherSuite) == NID_kx_rsa)
    {
        utils::DataReader reader("ClientKeyExchange", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        const auto encryptedPreMaster = reader.get_span(2, 0, 65535);
        reader.assert_done();

        auto ctx = crypto::CryptoManager::getInstance().createKeyContext(serverKey_);
        crypto::ThrowIfFalse(ctx != nullptr);

        crypto::ThrowIfFalse(0 < EVP_PKEY_decrypt_init(ctx));
        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_WITH_TLS_PADDING));

        OSSL_PARAM params[2];
        unsigned int value = metaInfo_.version.code();
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
    }*/
}

void Session::processFinished(const std::int8_t sideIndex, const Finished& finished)
{
    /// Check Finished data

    switch (metaInfo_.version.code())
    {
    case ProtocolVersion::TLSv1_3:
    {
        const auto& secret = (sideIndex == 0 ? keyInfo_.clientHndTrafficSecret : keyInfo_.serverHndTrafficSecret);
        if (!secret.empty())
        {
            const auto& digest = CipherSuiteGetHandshakeDigest(metaInfo_.cipherSuite);
            const auto digestName = HashTraits::getName(digest);

            crypto::SecureArray<uint8_t, TLS_MAX_MAC_LENGTH> finishedKey;
            size_t keySize = HashTraits::getSize(digest);

            crypto::DeriveFinishedKey(digestName, secret, {finishedKey.data(), keySize});

            crypto::KeyPtr hmacKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, finishedKey.data(), keySize));
            ThrowIfFalse(hmacKey);

            std::array<uint8_t, EVP_MAX_MD_SIZE> hashBuffer;
            HashTraits::hashInit(hashCtx_, handshakeHashAlg_);
            HashTraits::hashUpdate(hashCtx_, handshakeBuffer_);
            auto transcriptHash = HashTraits::hashFinal(hashCtx_, hashBuffer);

            std::array<uint8_t, TLS_MAX_MAC_LENGTH> sigBuffer;
            Signature::signInit(hashCtx_, digest, hmacKey);
            Signature::signUpdate(hashCtx_, transcriptHash);
            auto actual = Signature::signFinal(hashCtx_, sigBuffer);

            casket::ThrowIfFalse(finished.verifyData.size() == actual.size() &&
                                     std::equal(finished.verifyData.begin(), finished.verifyData.end(), actual.begin()),
                                 "Bad Finished MAC");
        }
        break;
    }
    case ProtocolVersion::TLSv1_2:
    case ProtocolVersion::TLSv1_1:
    case ProtocolVersion::TLSv1_0:
    {
        if (!keyInfo_.masterSecret.empty())
        {
            std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
            HashTraits::hashInit(hashCtx_, handshakeHashAlg_);
            HashTraits::hashUpdate(hashCtx_, handshakeBuffer_);
            auto transcriptHash = HashTraits::hashFinal(hashCtx_, buffer);

            std::array<uint8_t, TLS1_FINISH_MAC_LENGTH> actual;

            PRF(keyInfo_.masterSecret, (sideIndex == 0 ? "client finished" : "server finished"), transcriptHash, {},
                actual);

            casket::ThrowIfFalse(finished.verifyData.size() == actual.size() &&
                                     std::equal(finished.verifyData.begin(), finished.verifyData.end(), actual.begin()),
                                 "Bad Finished MAC");
        }
        break;
    }
    case ProtocolVersion::SSLv3_0:
        /// @todo: do it.
        break;
    }

    /// Generate key material

    if (metaInfo_.version == tls::ProtocolVersion::TLSv1_3)
    {
        if (sideIndex == 0)
        {
            const auto digestName = CipherSuiteGetHandshakeDigestName(metaInfo_.cipherSuite);

            crypto::DeriveKey(digestName, keyInfo_.clientAppTrafficSecret, keyInfo_.clientEncKey);
            crypto::DeriveIV(digestName, keyInfo_.clientAppTrafficSecret, keyInfo_.clientIV);

            seqnum_.resetClientSequence();

            if (debugKeys_)
            {
                utils::printHex(std::cout, keyInfo_.clientEncKey, Colorize("Client Write key"));
                utils::printHex(std::cout, keyInfo_.clientIV, Colorize("Client IV"));
            }
        }
        else
        {
            const auto digestName = CipherSuiteGetHandshakeDigestName(metaInfo_.cipherSuite);

            crypto::DeriveKey(digestName, keyInfo_.serverAppTrafficSecret, keyInfo_.serverEncKey);
            crypto::DeriveIV(digestName, keyInfo_.serverAppTrafficSecret, keyInfo_.serverIV);

            seqnum_.resetServerSequence();

            if (debugKeys_)
            {
                utils::printHex(std::cout, keyInfo_.serverEncKey, Colorize("Server Write key"));
                utils::printHex(std::cout, keyInfo_.serverIV, Colorize("Server IV"));
            }
        }
    }
}

void Session::processNewSessionTicket(const NewSessionTicket& sessionTicket)
{
    /// @todo: support it.
    (void)sessionTicket;
}

void Session::processKeyUpdate(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    /// @todo: handle requested and not requested mode
    casket::ThrowIfFalse(message.subspan(TLS_HANDSHAKE_HEADER_SIZE).size_bytes() == 1, "invalid KeyUpdate message");

    const auto digestName = CipherSuiteGetHandshakeDigestName(metaInfo_.cipherSuite);

    if (sideIndex == 0)
    {
        crypto::UpdateTrafficSecret(digestName, keyInfo_.clientAppTrafficSecret);

        crypto::DeriveKey(digestName, keyInfo_.clientAppTrafficSecret, keyInfo_.clientEncKey);
        crypto::DeriveIV(digestName, keyInfo_.clientAppTrafficSecret, keyInfo_.clientIV);

        seqnum_.resetClientSequence();
    }
    else
    {
        crypto::UpdateTrafficSecret(digestName, keyInfo_.serverAppTrafficSecret);

        crypto::DeriveKey(digestName, keyInfo_.serverAppTrafficSecret, keyInfo_.serverEncKey);
        crypto::DeriveIV(digestName, keyInfo_.serverAppTrafficSecret, keyInfo_.serverIV);

        seqnum_.resetServerSequence();
    }
}

void Session::fetchAlgorithms()
{
    // Don't call for unknown protocol version and cipher suite

    assert(metaInfo_.version != ProtocolVersion());
    assert(metaInfo_.cipherSuite != nullptr);

    auto isAEAD = false;
    auto cipherName = CipherSuiteGetCipherName(metaInfo_.cipherSuite);

    if (!casket::iequals(cipherName, "UNDEF"))
    {
        cipherAlg_ = CryptoManager::getInstance().fetchCipher(cipherName);
        isAEAD = CipherTraits::isAEAD(cipherAlg_);

        if (isAEAD)
        {
            recordLayer_.enableAEAD();
            recordLayer_.setTagLength(
                CipherSuiteManager::getInstance().getTagLengthByID(CipherSuiteGetID(metaInfo_.cipherSuite)));
        }

        /// Detect lengths for encryption keys and IV
        if (metaInfo_.version == ProtocolVersion::TLSv1_3)
        {
            auto keySize = CipherTraits::getKeyLength(cipherAlg_);
            keyInfo_.clientEncKey.resize(keySize);
            keyInfo_.serverEncKey.resize(keySize);

            /// @todo: fix constant.
            keyInfo_.clientIV.resize(12);
            keyInfo_.serverIV.resize(12);
        }
        else
        {
            auto keySize = CipherTraits::getKeyLength(cipherAlg_);
            keyInfo_.clientEncKey.resize(keySize);
            keyInfo_.serverEncKey.resize(keySize);

            auto ivSize = CipherTraits::getIVLengthWithinKeyBlock(cipherAlg_);
            keyInfo_.clientIV.resize(ivSize);
            keyInfo_.serverIV.resize(ivSize);
        }
    }

    // TLSv1.3 uses only AEAD, so don't check for version
    if (!isAEAD)
    {
        hmacHashAlg_ = CryptoManager::getInstance().fetchDigest(CipherSuiteGetHmacDigestName(metaInfo_.cipherSuite));
    }

    handshakeHashAlg_ = CryptoManager::getInstance().fetchDigest(getHashAlgorithm());
}

} // namespace snet::tls