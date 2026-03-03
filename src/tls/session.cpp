#include <cassert>
#include <limits>
#include <memory>
#include <utility>

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
#include <snet/crypto/rand.hpp>

#include <snet/tls/session.hpp>
#include <snet/tls/record_layer.hpp>
#include <snet/tls/cipher_suite_manager.hpp>
#include <snet/tls/policy.hpp>

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
    , pendingRecords_(64)
    , outgoingRecords_(64)
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
    handshakeBuffer_.clear();

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

size_t Session::readRecords(nonstd::span<const uint8_t> input)
{
    if (input.empty())
    {
        return 0;
    }

    size_t processedLength = 0;

    while (processedLength < input.size())
    {
        if (!readingRecord_)
        {
            if (input.size() - processedLength < TLS_HEADER_SIZE)
            {
                break;
            }

            readingRecord_ = recordPool_.acquire();
            if (!readingRecord_)
            {
                return processedLength;
            }

            try
            {
                readingRecord_->deserializeHeader(input.subspan(processedLength, TLS_HEADER_SIZE));
                processedLength += TLS_HEADER_SIZE;
            }
            catch (const std::exception& e)
            {
                std::cerr << "Failed to parse TLS header: " << e.what() << std::endl;
                recordPool_.release(std::exchange(readingRecord_, nullptr));
                throw;
            }
        }

        const size_t payloadProcessed = readingRecord_->initCiphertext(input.subspan(processedLength));
        processedLength += payloadProcessed;

        if (readingRecord_->isFullyAssembled())
        {
            if (pendingRecords_.push(readingRecord_))
            {
                readingRecord_ = nullptr;
            }
            else
            {
                recordPool_.release(std::exchange(readingRecord_, nullptr));
                return processedLength;
            }
        }
    }

    if (readingRecord_ && processedLength == 0)
    {
        recordPool_.release(std::exchange(readingRecord_, nullptr));
    }

    return processedLength;
}

size_t Session::writeRecords(nonstd::span<uint8_t> output)
{
    size_t written = 0;

    while (!outgoingRecords_.empty() && written < output.size())
    {
        Record* record{nullptr};

        if (!outgoingRecords_.pop(record))
        {
            break;
        }

        nonstd::span<const uint8_t> data = record->isPlaintext() ? record->getPlaintext() : record->getCiphertext();

        size_t totalNeeded = TLS_HEADER_SIZE + data.size();
        if (output.size() - written < totalNeeded)
        {
            break;
        }

        size_t headerSize = record->serializeHeader(output.subspan(written, TLS_HEADER_SIZE));

        std::copy(data.begin(), data.end(), output.begin() + written + headerSize);

        written += headerSize + data.size();
        recordPool_.release(record);
    }

    return written;
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
        data = record->getCiphertext();
    }

    if (record->getType() == RecordType::ChangeCipherSpec)
    {
        casket::ThrowIfFalse(data.size() == 1 && data[0] == 0x01, "Malformed Change Cipher Spec message");
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
            break;
        }
        case HandshakeType::ServerHelloCode:
        {
            casket::ThrowIfFalse(sideIndex == 1, "Incorrect side index");
            processServerHello(record->getHandshake<ServerHello>());
            break;
        }
        case HandshakeType::EncryptedExtensionsCode:
        {
            casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
            processEncryptedExtensions(record->getHandshake<EncryptedExtensions>());
            break;
        }
        case HandshakeType::ServerHelloDoneCode:
        {
            casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
            break;
        }
        case HandshakeType::ServerKeyExchangeCode:
        {
            casket::ThrowIfFalse(sideIndex == 1, "Incorrect side index");
            processServerKeyExchange(record->getHandshake<ServerKeyExchange>());
            break;
        }
        case HandshakeType::ClientKeyExchangeCode:
        {
            casket::ThrowIfFalse(sideIndex == 0, "Incorrect side index");
            processClientKeyExchange(record->getHandshake<ClientKeyExchange>());
            break;
        }
        case HandshakeType::CertificateCode:
        {
            processCertificate(sideIndex, record->getHandshake<Certificate>());
            break;
        }
        case HandshakeType::CertificateRequestCode:
        {
            processCertificateRequest(sideIndex, record->getHandshake<CertificateRequest>());
            break;
        }
        case HandshakeType::CertificateVerifyCode:
        {
            processCertificateVerify(sideIndex, record->getHandshake<CertificateVerify>());
            break;
        }
        case HandshakeType::FinishedCode:
        {
            processFinished(sideIndex, record->getHandshake<Finished>());
            break;
        }
        case HandshakeType::NewSessionTicketCode:
        {
            casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
            processNewSessionTicket(record->getHandshake<NewSessionTicket>());
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
    nonstd::span<const uint8_t> data;

    if (record->isPlaintext() && record->getType() != RecordType::ChangeCipherSpec)
    {
        data = record->getPlaintext();
    }
    else
    {
        /// @todo: does it really need???
        data = record->getCiphertext();
    }

    if (record->getType() == RecordType::Handshake)
    {
        switch (record->getHandshakeType())
        {
        case HandshakeType::ClientHelloCode:
        case HandshakeType::ServerHelloCode:
        case HandshakeType::EncryptedExtensionsCode:
        case HandshakeType::ServerHelloDoneCode:
        case HandshakeType::ServerKeyExchangeCode:
        case HandshakeType::ClientKeyExchangeCode:
        case HandshakeType::CertificateCode:
        case HandshakeType::CertificateRequestCode:
        case HandshakeType::CertificateVerifyCode:
        {
            std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            break;
        }
        case HandshakeType::FinishedCode:
        {
            if (metaInfo_.version == ProtocolVersion::TLSv1_3 || sideIndex == 0)
            {
                std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            }
            break;
        }
        case HandshakeType::NewSessionTicketCode:
        {
            if (metaInfo_.version < ProtocolVersion::TLSv1_3)
            {
                // RFC 5077: 3.3 (must be included in transcript hash)
                std::copy(data.begin(), data.end(), std::back_inserter(handshakeBuffer_));
            }
            break;
        }
        case HandshakeType::KeyUpdateCode:
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

void Session::keySchedule(const std::int8_t sideIndex, Record* record)
{
    if (getVersion() < ProtocolVersion::TLSv1_3)
    {
        if (record->getType() == RecordType::ChangeCipherSpec)
        {
            if (!monitor_)
            {
                generateMasterSecret();
                generateKeyMaterial(sideIndex);
            }
            cipherState_ |= (sideIndex == 0 ? 1 : 2);
        }
        
    }
    else
    {
        if (record->getType() == RecordType::Handshake)
        {
            if (record->getHandshakeType() == HandshakeType::ServerHelloCode)
            {
                if (!monitor_)
                {
                    generateHandshakeTrafficSecrets();
                    generateHandshakeKeyAndIv();
                }
            }
            else if (record->getHandshakeType() == HandshakeType::FinishedCode)
            {
                if (!monitor_)
                {
                    generateTLSv13MasterSecret();
                    generateApplicationTrafficSecrets();
                    generateApplicationKeyAndIv(sideIndex);
                }

                /// @todo: pay attention to the HelloRetryRequest
                cipherState_ |= (sideIndex == 0 ? 1 : 2);
            }
        }
    }
}

void Session::encrypt(const int8_t sideIndex, Record* record)
{
    if (sideIndex == 0)
    {
        recordLayer_.encrypt(clientCipherCtx_, hmacCtx_, hashCtx_, hmacHashAlg_, record, seqnum_.getClientSequence(),
                             keyInfo_.clientEncKey, keyInfo_.clientMacKey, keyInfo_.clientIV);
        seqnum_.acceptClientSequence();
    }
    else
    {
        recordLayer_.encrypt(serverCipherCtx_, hmacCtx_, hashCtx_, hmacHashAlg_, record, seqnum_.getServerSequence(),
                             keyInfo_.serverEncKey, keyInfo_.serverMacKey, keyInfo_.serverIV);
        seqnum_.acceptServerSequence();
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

void Session::generateHandshakeSecret(Key* publicKey, Key* privateKey)
{
    auto ecdheSecret = GroupParams::deriveSecret(privateKey, publicKey, true);

    /// RFC 8446. Section 7.1.

    /// Generation of early_secret.
    keyInfo_.earlySecret.resize(HashTraits::getSize(handshakeHashAlg_));
    GenerateSecret(handshakeHashAlg_, {}, {}, keyInfo_.earlySecret);

    /// Generation of handshake_secret.
    keyInfo_.handshakeSecret.resize(HashTraits::getSize(handshakeHashAlg_));
    GenerateSecret(handshakeHashAlg_, keyInfo_.earlySecret, ecdheSecret, keyInfo_.handshakeSecret);
}

void Session::generateHandshakeTrafficSecrets()
{
    if (!keyInfo_.handshakeSecret.empty())
    {
        std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
        auto transcriptHash = getTranscriptHash(buffer);

        keyInfo_.clientHndTrafficSecret.resize(HashTraits::getSize(handshakeHashAlg_));
        keyInfo_.serverHndTrafficSecret.resize(HashTraits::getSize(handshakeHashAlg_));

        DeriveClientHsTraffic(handshakeHashAlg_, keyInfo_.handshakeSecret, transcriptHash,
                              keyInfo_.clientHndTrafficSecret);
        DeriveServerHsTraffic(handshakeHashAlg_, keyInfo_.handshakeSecret, transcriptHash,
                              keyInfo_.serverHndTrafficSecret);
    }
}

void Session::generateMasterSecret()
{
    /// If not setted
    if (keyInfo_.masterSecret.empty())
    {
        ThrowIfTrue(PMS_.empty(), "Premaster secret not setted");
        keyInfo_.masterSecret.resize(TLS_MASTER_SECRET_SIZE);

        if (serverExtensions_.has(tls::ExtensionCode::ExtendedMasterSecret))
        {
            std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
            auto transcriptHash = getTranscriptHash(buffer);
            PRF(PMS_, "extended master secret", transcriptHash, {}, keyInfo_.masterSecret);
        }
        else
        {
            PRF(PMS_, "master secret", clientRandom_, serverRandom_, keyInfo_.masterSecret);
        }
    }
}

void Session::generateTLSv13MasterSecret()
{
    if (!keyInfo_.handshakeSecret.empty())
    {
        /// Generation of master_secret.
        keyInfo_.masterSecret.resize(HashTraits::getSize(handshakeHashAlg_));
        GenerateSecret(handshakeHashAlg_, keyInfo_.handshakeSecret, {}, keyInfo_.masterSecret);
    }
}

void Session::generateApplicationTrafficSecrets()
{
    if (!keyInfo_.masterSecret.empty())
    {
        std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
        auto transcriptHash = getTranscriptHash(buffer);

        keyInfo_.clientAppTrafficSecret.resize(HashTraits::getSize(handshakeHashAlg_));
        keyInfo_.serverAppTrafficSecret.resize(HashTraits::getSize(handshakeHashAlg_));

        DeriveClientApTraffic(handshakeHashAlg_, keyInfo_.masterSecret, transcriptHash,
                              keyInfo_.clientAppTrafficSecret);
        DeriveServerApTraffic(handshakeHashAlg_, keyInfo_.masterSecret, transcriptHash,
                              keyInfo_.serverAppTrafficSecret);
    }
}

void Session::generateKeyMaterial(const int8_t sideIndex)
{
    if (!keyInfo_.isValid(ProtocolVersion::TLSv1_2))
    {
        return;
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

void Session::generateHandshakeKeyAndIv()
{
    assert(!keyInfo_.clientHndTrafficSecret.empty());
    assert(!keyInfo_.serverHndTrafficSecret.empty());

    const auto digestName = HashTraits::getName(handshakeHashAlg_);

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

void Session::generateApplicationKeyAndIv(const int8_t sideIndex)
{
    if (sideIndex == 0)
    {
        assert(!keyInfo_.clientAppTrafficSecret.empty());
        const auto digestName = HashTraits::getName(handshakeHashAlg_);

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
        assert(!keyInfo_.serverAppTrafficSecret.empty());
        const auto digestName = HashTraits::getName(handshakeHashAlg_);

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

void Session::constructClientHello(ClientHello& clientHello)
{
    metaInfo_.version = clientHello.version;

    Rand::generate(clientRandom_);
    clientHello.random = clientRandom_;

    /// @todo: filter ciphersuites

    if (metaInfo_.version != ProtocolVersion::SSLv3_0)
    {
        clientExtensions_.deserialize(Side::Client, clientHello.extensions, HandshakeType::ClientHelloCode);

        if (clientExtensions_.has(ExtensionCode::KeyShare))
        {
            auto keyShare = clientExtensions_.take<KeyShare>();
            auto offeredGroups = keyShare->offeredGroups();
            auto firstGroup = offeredGroups.front();

            /// @todo: check offered group by policy

            ephemeralPrivateKey_ = GroupParams::generateKeyByParams(firstGroup);
            keyShare->setPublicKey(0, ephemeralPrivateKey_);

            clientExtensions_.add(std::move(keyShare));
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

void Session::constructCertificate(const int8_t sideIndex, Record* record)
{
    Certificate certificate;

    if (metaInfo_.version == ProtocolVersion::TLSv1_3)
    {
        TLSv13Certificate message;
        TLSv13Certificate::Entry entry;

        entry.cert = sideIndex == 0 ? clientCert_.get() : serverCert_.get();
        entry.extensions = nullptr;

        message.entryList[0] = std::move(entry);
        message.entryCount = 1;

        certificate.message = std::move(message);

        record->serializeHandshake(HandshakeMessage(std::move(certificate), HandshakeType::CertificateCode), sideIndex,
                                   *this);
    }
    else
    {
        TLSv1Certificate message;
        TLSv1Certificate::Entry entry;

        entry.cert = sideIndex == 0 ? clientCert_.get() : serverCert_.get();

        message.entryList[0] = std::move(entry);
        message.entryCount = 1;

        certificate.message = std::move(message);

        record->serializeHandshake(HandshakeMessage(std::move(certificate), HandshakeType::CertificateCode), sideIndex,
                                   *this);
    }
}

void Session::constructCertificateVerify(const int8_t sideIndex, Record* record)
{
    if (metaInfo_.version == ProtocolVersion::TLSv1_3)
    {
        CertificateVerify certVerify;
        std::array<uint8_t, EVP_MAX_MD_SIZE> transcriptHashBuffer;

        /// @todo: keep your mind for client side.

        ThrowIfFalse(clientExtensions_.has<SignatureAlgorithms>(), "SignatureAlgorithms extensions not found");
        auto sigAlgs = clientExtensions_.get<SignatureAlgorithms>();

        Key* privateKey = (sideIndex == 1 ? serverKey_.get() : nullptr);
        auto scheme =
            ChooseSignatureScheme(privateKey, SignatureScheme::supportedSchemes(), sigAlgs->supportedSchemes());

        auto transcriptHash = getTranscriptHash(transcriptHashBuffer);
        std::vector<uint8_t> signatureBuffer(crypto::AsymmKey::getKeySize(privateKey));
        auto signature =
            CertificateVerify::doTLSv13Sign(scheme, sideIndex, hashCtx_, privateKey, transcriptHash, signatureBuffer);

        certVerify.scheme = scheme;
        certVerify.signature = signature;

        record->serializeHandshake(HandshakeMessage(std::move(certVerify), HandshakeType::CertificateVerifyCode),
                                   sideIndex, *this);
    }
}

void Session::constructServerKeyExchange(const int8_t sideIndex, Record* record)
{
    ServerKeyExchange keyExchange;

    const auto& supportedGroupsByPeer = clientExtensions_.get<SupportedGroups>();

    /// @todo 512 - it's magic number which must be replaced
    std::array<uint8_t, 2 * TLS_RANDOM_SIZE + 512> tbsBuffer;
    size_t tbsLength = 0;
    size_t tbsParamsStart = 0;

    std::copy(clientRandom_.begin(), clientRandom_.end(), tbsBuffer.data() + tbsLength);
    tbsLength += TLS_RANDOM_SIZE;

    std::copy(serverRandom_.begin(), serverRandom_.end(), tbsBuffer.data() + tbsLength);
    tbsLength += TLS_RANDOM_SIZE;

    tbsParamsStart = tbsLength;

    std::vector<uint8_t> signatureBuffer(crypto::AsymmKey::getKeySize(serverKey_));
    auto kex = CipherSuiteGetKeyExchange(metaInfo_.cipherSuite);

    if (kex == NID_kx_dhe)
    {
        auto& dheParams = keyExchange.params.emplace<DhParams>();

        /// @todo: get DH params

        auto serializedLength =
            dheParams.serialize({tbsBuffer.data() + tbsParamsStart, tbsBuffer.size() - tbsParamsStart});
        keyExchange.data = {tbsBuffer.data() + tbsParamsStart, serializedLength};
        tbsLength += serializedLength;
    }
    else if (kex == NID_kx_ecdhe || kex == NID_kx_ecdhe_psk)
    {
        sharedGroupParams_ = ChooseKeyExchangeGroup(supportedGroupsByPeer->getEcGroups(), {});
        casket::ThrowIfTrue(sharedGroupParams_ == GroupParams::NONE, "No shared ECC group with client");

        ephemeralPrivateKey_ = GroupParams::generateKeyByParams(sharedGroupParams_);

        auto& ecdheParams = keyExchange.params.emplace<EcdheParams>();
        auto encodedKey = AsymmKey::getEncodedPublicKey(ephemeralPrivateKey_);

        ecdheParams.curveType = 3;
        ecdheParams.curveID = sharedGroupParams_;
        ecdheParams.publicPoint = encodedKey;

        auto serializedLength =
            ecdheParams.serialize({tbsBuffer.data() + tbsParamsStart, tbsBuffer.size() - tbsParamsStart});
        keyExchange.data = {tbsBuffer.data() + tbsParamsStart, serializedLength};
        tbsLength += serializedLength;
    }
    else if (kex != NID_kx_psk)
    {
        throw std::runtime_error("ServerKeyExchange::serialize: Unsupported kex type");
    }

    auto auth = CipherSuiteGetAuth(metaInfo_.cipherSuite);
    if (auth == NID_auth_rsa || auth == NID_auth_dss || auth == NID_auth_ecdsa)
    {
        /// @todo: what to do if no extensions
        const auto& peerSigAlgs = clientExtensions_.get<SignatureAlgorithms>();
        const auto& supportedSigAlgs = SignatureScheme::supportedSchemes();
        auto scheme = ChooseSignatureScheme(serverKey_, supportedSigAlgs, peerSigAlgs->supportedSchemes());

        if (metaInfo_.version == ProtocolVersion::TLSv1_2)
        {
            keyExchange.scheme = scheme;
        }

        HashAlg hash{nullptr};

        auto hashName = scheme.getHashAlgorithm();
        if (!casket::equals(hashName, "UNDEF"))
        {
            hash = CryptoManager::getInstance().fetchDigest(hashName);
        }

        keyExchange.signature = Signature::signMessage(hashCtx_, scheme.getKeyAlgorithm(), hash, serverKey_,
                                                       signatureBuffer, {tbsBuffer.data(), tbsLength});
    }

    record->serializeHandshake(HandshakeMessage(std::move(keyExchange), HandshakeType::ServerKeyExchangeCode),
                               sideIndex, *this);
}

void Session::constructClientKeyExchange(const int8_t sideIndex, Record* record)
{
    ClientKeyExchange keyExchange;
    std::vector<uint8_t> publicKey;

    auto kex = CipherSuiteGetKeyExchange(metaInfo_.cipherSuite);

    if (kex == NID_kx_ecdhe)
    {
        ephemeralPrivateKey_ = GroupParams::generateKeyByParams(sharedGroupParams_);
        publicKey = AsymmKey::getEncodedPublicKey(ephemeralPrivateKey_);

        auto& ecdh = keyExchange.params.emplace<ClientEcdhPublic>();
        ecdh.ecdhPublic = publicKey;
    }

    
    PMS_ = GroupParams::deriveSecret(ephemeralPrivateKey_, peerPublicKey_, false);

    record->serializeHandshake(HandshakeMessage(std::move(keyExchange), HandshakeType::ClientKeyExchangeCode),
                               sideIndex, *this);
}

void Session::constructServerHelloDone(const int8_t sideIndex, Record* record)
{
    record->serializeHandshake(HandshakeMessage(ServerHelloDone(), HandshakeType::ServerHelloDoneCode), sideIndex,
                               *this);
}

void Session::constructFinished(const int8_t sideIndex, Record* record)
{
    if (metaInfo_.version == ProtocolVersion::TLSv1_3)
    {
        Finished finished;

        const auto& secret = (sideIndex == 0 ? keyInfo_.clientHndTrafficSecret : keyInfo_.serverHndTrafficSecret);
        const auto& digest = CipherSuiteGetHandshakeDigest(metaInfo_.cipherSuite);
        const auto digestName = HashTraits::getName(digest);

        crypto::SecureArray<uint8_t, TLS_MAX_MAC_LENGTH> finishedKey;
        size_t keySize = HashTraits::getSize(digest);

        crypto::DeriveFinishedKey(digestName, secret, {finishedKey.data(), keySize});

        crypto::KeyPtr hmacKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, finishedKey.data(), keySize));
        ThrowIfFalse(hmacKey);

        std::array<uint8_t, EVP_MAX_MD_SIZE> hashBuffer;
        auto transcriptHash = getTranscriptHash(hashBuffer);

        std::array<uint8_t, TLS_MAX_MAC_LENGTH> sigBuffer;
        Signature::signInit(hashCtx_, digest, hmacKey);
        Signature::signUpdate(hashCtx_, transcriptHash);
        auto actual = Signature::signFinal(hashCtx_, sigBuffer);

        finished.verifyData = actual;

        record->serializeHandshake(HandshakeMessage(std::move(finished), HandshakeType::FinishedCode), sideIndex,
                                   *this);
    }
}

void Session::processCertificateVerify(const int8_t sideIndex, const CertificateVerify& certVerify)
{
    KeyPtr publicKey{nullptr};
    HashAlg hash{nullptr};

    if (metaInfo_.version == ProtocolVersion::TLSv1_3)
    {
        if (sideIndex == 0)
        {
            publicKey = Cert::publicKey(clientCert_);
        }
        else
        {
            publicKey = Cert::publicKey(serverCert_);
        }

        std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
        auto transcriptHash = getTranscriptHash(buffer);
        HashTraits::resetContext(hashCtx_);
        CertificateVerify::doTLSv13Verify(certVerify, sideIndex, hashCtx_, publicKey, transcriptHash);
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

        HashTraits::resetContext(hashCtx_);
        Signature::verifyMessage(hashCtx_, certVerify.scheme.getKeyAlgorithm(), hash, publicKey, certVerify.signature,
                                 handshakeBuffer_);
    }
}

void Session::processEncryptedExtensions(const EncryptedExtensions& encryptedExtensions)
{
    serverEncExtensions_.deserialize(Side::Server, encryptedExtensions.extensions,
                                     HandshakeType::EncryptedExtensionsCode);
}

void Session::processServerKeyExchange(const ServerKeyExchange& keyExchange)
{
    if (std::holds_alternative<EcdheParams>(keyExchange.params))
    {
        const auto& ecdhe = std::get<EcdheParams>(keyExchange.params);
        sharedGroupParams_ = ecdhe.curveID;

        KeyPtr publicKey = GroupParams::generateParams(sharedGroupParams_);
        AsymmKey::setEncodedPublicKey(publicKey, ecdhe.publicPoint);
        peerPublicKey_ = std::move(publicKey);
    }

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

        HashTraits::resetContext(hashCtx_);
        Signature::verifyMessage(hashCtx_, keyExchange.scheme.getKeyAlgorithm(), hash, publicKey, keyExchange.signature,
                                 tbs);
    }
}

void Session::processClientKeyExchange(const ClientKeyExchange& keyExchange)
{
    if (monitor_ || !keyInfo_.masterSecret.empty())
    {
        return;
    }

    if (std::holds_alternative<ClientEcdhPublic>(keyExchange.params))
    {
        const auto& params = std::get<ClientEcdhPublic>(keyExchange.params);
        KeyPtr publicKey = GroupParams::generateParams(sharedGroupParams_);
        AsymmKey::setEncodedPublicKey(publicKey, params.ecdhPublic);
        peerPublicKey_ = std::move(publicKey);
    }

    PMS_ = GroupParams::deriveSecret(ephemeralPrivateKey_, peerPublicKey_, false);


    /*if (CipherSuiteGetKeyExchange(metaInfo_.cipherSuite) == NID_kx_rsa)
    {
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
            auto transcriptHash = getTranscriptHash(hashBuffer);

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
            auto transcriptHash = getTranscriptHash(buffer);

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

    const auto digestName = HashTraits::getName(handshakeHashAlg_);

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

            keyInfo_.clientIV.resize(TLS13_AEAD_NONCE_SIZE);
            keyInfo_.serverIV.resize(TLS13_AEAD_NONCE_SIZE);
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