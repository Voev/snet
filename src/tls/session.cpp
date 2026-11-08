#include <cassert>
#include <limits>
#include <memory>
#include <utility>

#include <casket/utils/exception.hpp>
#include <casket/utils/hexlify.hpp>
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
#include <snet/tls/policy/client_hello_policy.hpp>
#include <snet/tls/signature_hash.hpp>

#include <snet/tls/record_printer.hpp>

#include <openssl/evp.h>

using namespace snet::crypto;

inline std::string Colorize(nonstd::string_view text)
{
    return casket::format("[{}]", text);
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
{
}

void Session::reset() noexcept
{
    recordLayer_.reset();
    handshakeBuffer_.clear();

    hmacHashAlg_ = nullptr;
    cipherAlg_ = nullptr;

    flags_.clearAll();

    CipherTraits::resetContext(clientCipherCtx_);
    CipherTraits::resetContext(serverCipherCtx_);
    HashTraits::resetContext(hashCtx_);
}

bool Session::getCipherState(const std::int8_t sideIndex) const noexcept
{
    return flags_.test(sideIndex == 0 ? SessionBit::ClientCipherActive
                                      : SessionBit::ServerCipherActive);
}

bool Session::canDecrypt(const std::int8_t sideIndex) const noexcept
{
    return flags_.test(sideIndex == 0 ? SessionBit::ClientCanDecrypt
                                      : SessionBit::ServerCanDecrypt);
}

size_t Session::readRecords(nonstd::span<const uint8_t> input)
{
    if (input.empty())
        return 0;

    size_t processedLength = 0;

    while (processedLength < input.size())
    {
        if (!readingRecord_)
        {
            if (input.size() - processedLength < TLS_HEADER_SIZE)
                break;

            readingRecord_ = recordPool_.acquire();
            if (!readingRecord_)
                return processedLength;

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
            if (!pendingRecords_.tryPush(readingRecord_))
            {
                // pendingRecords_ overflow: caller is not draining incoming
                // records between readRecords() calls. Silent drop or rollback
                // would corrupt the record stream (rollback re-parses payload
                // bytes as a new header on retry; drop loses TLS data).
                // Abort loudly.
                recordPool_.release(std::exchange(readingRecord_, nullptr));
                casket::ThrowIfTrue(false,
                                    "pendingRecords_ overflow ({} slots): caller must drain "
                                    "pending records between readRecords() calls",
                                    pendingRecords_.capacity());
            }
            readingRecord_ = nullptr;
        }
    }

    return processedLength;
}

size_t Session::writeRecords(nonstd::span<uint8_t> output)
{
    size_t written = 0;

    while (!outgoingRecords_.empty() && written < output.size())
    {
        Record* record = outgoingRecords_.front();

        auto data = record->isPlaintext() ? record->getPlaintext() : record->getCiphertext();

        const size_t totalNeeded = TLS_HEADER_SIZE + data.size();
        if (output.size() - written < totalNeeded)
        {
            break;
        }

        outgoingRecords_.pop();
        const size_t headerSize = record->serializeHeader(output.subspan(written, TLS_HEADER_SIZE));
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
            processKeyUpdate(sideIndex, record->getHandshake<KeyUpdate>());
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
    if (record->getType() != RecordType::Handshake)
    {
        return;
    }

    nonstd::span<const uint8_t> data;

    if (record->isPlaintext())
    {
        data = record->getPlaintextOffset();
    }
    else
    {
        data = record->getCiphertext();
    }

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
    default:
        break;
    }
}

void Session::keySchedule(const std::int8_t sideIndex, bool encrypt, Record* record)
{
    if (getVersion() < ProtocolVersion::TLSv1_3)
    {
        if (record->getType() == RecordType::ChangeCipherSpec)
        {
            if (!flags_.test(SessionBit::Monitor))
            {
                generateMasterSecret();
                generateKeyMaterial(sideIndex, encrypt);
            }

            flags_.set(sideIndex == 0 ? SessionBit::ClientCipherActive : SessionBit::ServerCipherActive);
        }
    }
    else
    {
        if (record->getType() == RecordType::Handshake)
        {
            if (record->getHandshakeType() == HandshakeType::ServerHelloCode)
            {
                if (!flags_.test(SessionBit::Monitor))
                {
                    generateHandshakeTrafficSecrets();
                    generateHandshakeKeyAndIv(encrypt);
                }
            }
            else if (record->getHandshakeType() == HandshakeType::FinishedCode)
            {
                if (!flags_.test(SessionBit::Monitor))
                {
                    generateTLSv13MasterSecret();
                    generateApplicationTrafficSecrets();
                    generateApplicationKeyAndIv(sideIndex, encrypt);
                }

                /// @todo: pay attention to the HelloRetryRequest
                flags_.set(sideIndex == 0 ? SessionBit::ClientCipherActive : SessionBit::ServerCipherActive);
            }
        }
    }
}

void Session::encrypt(const int8_t sideIndex, Record* record)
{
    if (sideIndex == 0)
    {
        recordLayer_.encrypt(clientCipherCtx_,
                             hmacCtx_,
                             hashCtx_,
                             hmacHashAlg_,
                             record,
                             seqnum_.getClientSequence(),
                             keyInfo_.clientMacKey,
                             keyInfo_.clientIV);
        seqnum_.acceptClientSequence();
    }
    else
    {
        recordLayer_.encrypt(serverCipherCtx_,
                             hmacCtx_,
                             hashCtx_,
                             hmacHashAlg_,
                             record,
                             seqnum_.getServerSequence(),
                             keyInfo_.serverMacKey,
                             keyInfo_.serverIV);
        seqnum_.acceptServerSequence();
    }
}

void Session::decrypt(const int8_t sideIndex, Record* record)
{
    if (sideIndex == 0)
    {
        recordLayer_.decrypt(clientCipherCtx_,
                             hmacCtx_,
                             hashCtx_,
                             hmacHashAlg_,
                             record,
                             seqnum_.getClientSequence(),
                             keyInfo_.clientMacKey,
                             keyInfo_.clientIV);
        seqnum_.acceptClientSequence();
    }
    else
    {
        recordLayer_.decrypt(serverCipherCtx_,
                             hmacCtx_,
                             hashCtx_,
                             hmacHashAlg_,
                             record,
                             seqnum_.getServerSequence(),
                             keyInfo_.serverMacKey,
                             keyInfo_.serverIV);
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

        DeriveClientHsTraffic(
            handshakeHashAlg_, keyInfo_.handshakeSecret, transcriptHash, keyInfo_.clientHndTrafficSecret);
        DeriveServerHsTraffic(
            handshakeHashAlg_, keyInfo_.handshakeSecret, transcriptHash, keyInfo_.serverHndTrafficSecret);
    }
}

void Session::generateMasterSecret()
{
    /// If not setted
    if (keyInfo_.masterSecret.empty())
    {
        ThrowIfTrue(PMS_.empty(), "Premaster secret not setted");
        keyInfo_.masterSecret.resize(TLS_MASTER_SECRET_SIZE);

        if (flags_.test(SessionBit::UseExtendedMasterSecret))
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

        DeriveClientApTraffic(
            handshakeHashAlg_, keyInfo_.masterSecret, transcriptHash, keyInfo_.clientAppTrafficSecret);
        DeriveServerApTraffic(
            handshakeHashAlg_, keyInfo_.masterSecret, transcriptHash, keyInfo_.serverAppTrafficSecret);
    }
}

void Session::generateKeyMaterial(const int8_t sideIndex, bool encrypt)
{
    if (!keyInfo_.isValid(ProtocolVersion::TLSv1_2))
    {
        return;
    }

    if (flags_.test(SessionBit::DebugKeys))
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

        utils::DataReader reader(keyBlock);

        keyInfo_.clientEncKey.assign(reader.get_span_fixed(keySize));
        keyInfo_.serverEncKey.assign(reader.get_span_fixed(keySize));
        keyInfo_.clientIV.assign(reader.get_span_fixed(ivSize));
        keyInfo_.serverIV.assign(reader.get_span_fixed(ivSize));

        reader.assert_done();

        if (flags_.test(SessionBit::DebugKeys))
        {
            utils::printHex(std::cout, keyInfo_.clientEncKey, Colorize("Client Write key"));
            utils::printHex(std::cout, keyInfo_.clientIV, Colorize("Client IV"));
            utils::printHex(std::cout, keyInfo_.serverEncKey, Colorize("Server Write key"));
            utils::printHex(std::cout, keyInfo_.serverIV, Colorize("Server IV"));
        }

        if (sideIndex == 0)
        {
            recordLayer_.doTLSv1AeadInit(
                clientCipherCtx_, cipherAlg_, keyInfo_.clientEncKey, keyInfo_.clientIV, encrypt);
            flags_.set(SessionBit::ClientCanDecrypt);
        }
        else
        {
            recordLayer_.doTLSv1AeadInit(
                serverCipherCtx_, cipherAlg_, keyInfo_.serverEncKey, keyInfo_.serverIV, encrypt);
            flags_.set(SessionBit::ServerCanDecrypt);
        }
    }
    else
    {
        auto macSize = HashTraits::getSize(hmacHashAlg_);

        crypto::SecureArray<uint8_t, (TLS_MAX_MAC_LENGTH + TLS_MAX_KEY_LENGTH + TLS_MAX_IV_LENGTH) * 2> keyBlockBuffer;
        size_t keyBlockSize = (macSize + keySize + ivSize) * 2;

        auto keyBlock = nonstd::span(keyBlockBuffer.data(), keyBlockSize);

        PRF(keyInfo_.masterSecret, "key expansion", serverRandom_, clientRandom_, keyBlock);

        utils::DataReader reader(keyBlock);

        keyInfo_.clientMacKey.assign(reader.get_span_fixed(macSize));
        keyInfo_.serverMacKey.assign(reader.get_span_fixed(macSize));
        keyInfo_.clientEncKey.assign(reader.get_span_fixed(keySize));
        keyInfo_.serverEncKey.assign(reader.get_span_fixed(keySize));
        keyInfo_.clientIV.assign(reader.get_span_fixed(ivSize));
        keyInfo_.serverIV.assign(reader.get_span_fixed(ivSize));

        reader.assert_done();

        if (flags_.test(SessionBit::DebugKeys))
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
            RecordLayer::init(clientCipherCtx_, cipherAlg_, keyInfo_.clientEncKey, keyInfo_.clientIV, encrypt);
            flags_.set(SessionBit::ClientCanDecrypt);
        }
        else
        {
            RecordLayer::init(serverCipherCtx_, cipherAlg_, keyInfo_.serverEncKey, keyInfo_.serverIV, encrypt);
            flags_.set(SessionBit::ServerCanDecrypt);
        }
    }
}

void Session::generateHandshakeKeyAndIv(bool encrypt)
{
    assert(!keyInfo_.clientHndTrafficSecret.empty());
    assert(!keyInfo_.serverHndTrafficSecret.empty());

    const auto digestName = HashTraits::getName(handshakeHashAlg_);

    crypto::DeriveKey(digestName, keyInfo_.clientHndTrafficSecret, keyInfo_.clientEncKey);
    crypto::DeriveKey(digestName, keyInfo_.serverHndTrafficSecret, keyInfo_.serverEncKey);

    crypto::DeriveIV(digestName, keyInfo_.clientHndTrafficSecret, keyInfo_.clientIV);
    crypto::DeriveIV(digestName, keyInfo_.serverHndTrafficSecret, keyInfo_.serverIV);

    if (flags_.test(SessionBit::DebugKeys))
    {
        utils::printHex(std::cout, keyInfo_.serverEncKey, Colorize("Server Handshake Write key"));
        utils::printHex(std::cout, keyInfo_.serverIV, Colorize("Server Handshake IV"));
        utils::printHex(std::cout, keyInfo_.clientEncKey, Colorize("Client Handshake Write key"));
        utils::printHex(std::cout, keyInfo_.clientIV, Colorize("Client Handshake IV"));
    }

    recordLayer_.doTLSv13AeadInit(clientCipherCtx_, cipherAlg_, keyInfo_.clientEncKey, encrypt);
    recordLayer_.doTLSv13AeadInit(serverCipherCtx_, cipherAlg_, keyInfo_.serverEncKey, encrypt);

    flags_.set(SessionBit::ClientCanDecrypt);
    flags_.set(SessionBit::ServerCanDecrypt);
}

void Session::generateApplicationKeyAndIv(const int8_t sideIndex, bool encrypt)
{
    if (sideIndex == 0)
    {
        assert(!keyInfo_.clientAppTrafficSecret.empty());
        const auto digestName = HashTraits::getName(handshakeHashAlg_);

        crypto::DeriveKey(digestName, keyInfo_.clientAppTrafficSecret, keyInfo_.clientEncKey);
        crypto::DeriveIV(digestName, keyInfo_.clientAppTrafficSecret, keyInfo_.clientIV);

        seqnum_.resetClientSequence();

        recordLayer_.doTLSv13AeadInit(clientCipherCtx_, cipherAlg_, keyInfo_.clientEncKey, encrypt);

        if (flags_.test(SessionBit::DebugKeys))
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

        recordLayer_.doTLSv13AeadInit(serverCipherCtx_, cipherAlg_, keyInfo_.serverEncKey, encrypt);

        if (flags_.test(SessionBit::DebugKeys))
        {
            utils::printHex(std::cout, keyInfo_.serverEncKey, Colorize("Server Write key"));
            utils::printHex(std::cout, keyInfo_.serverIV, Colorize("Server IV"));
        }
    }
}

nonstd::string_view Session::getHashAlgorithm() const
{
    nonstd::string_view digest = HashTraits::getName(CipherSuiteGetHandshakeDigest(metaInfo_.cipherSuite));
    if (metaInfo_.version == ProtocolVersion::TLSv1_2 && digest == "MD5-SHA1")
    {
        return CipherSuiteGetHmacDigestName(metaInfo_.cipherSuite);
    }
    return digest;
}

void Session::PRF(nonstd::span<const uint8_t> secret, nonstd::string_view usage, nonstd::span<const uint8_t> rnd1,
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
        clientExtensions_.deserialize(Side::Client, clientHello.extensionsData, HandshakeType::ClientHelloCode);
    }
}

void Session::constructClientHello(const ClientHelloPolicy& policy)
{
    auto record = recordPool_.acquireScoped();
    casket::ThrowIfFalse(record.get() != nullptr, "record pool exhausted");

    // Version.
    const auto versions = policy.versions;
    casket::ThrowIfFalse(!versions.empty(), "no supported versions");

    const ProtocolVersion negotiated = versions.front();
    metaInfo_.version = negotiated;

    const ProtocolVersion legacyVersion =
        negotiated >= ProtocolVersion::TLSv1_3 ? ProtocolVersion::TLSv1_2 : negotiated;

    Rand::generate(clientRandom_);

    Extensions extensions;
    extensions.reserve(8);

    // SNI.
    if (negotiated > ProtocolVersion::SSLv3_0 && !policy.sni.empty())
        extensions.add(ServerNameIndicator{policy.sni});

    // supported_versions — TLS 1.3 only.
    if (negotiated >= ProtocolVersion::TLSv1_3)
    {
        SupportedVersions sv;
        for (auto v : versions)
            sv.addVersion(v);
        extensions.add(std::move(sv));
    }

    // supported_groups.
    std::array<crypto::GroupParams, 8> filteredGroupsBuf{};
    nonstd::span<const crypto::GroupParams> filteredGroups{};

    if (negotiated > ProtocolVersion::SSLv3_0 && !policy.groups.empty())
    {
        const auto ourGroups = crypto::GroupParams::getSupported();
        const std::size_t n = FilterGroups(policy.groups, ourGroups, filteredGroupsBuf);
        casket::ThrowIfFalse(n > 0, "no supported key exchange groups");

        filteredGroups = {filteredGroupsBuf.data(), n};

        SupportedGroups sg;
        for (auto g : filteredGroups)
            sg.addGroup(g);
        extensions.add(std::move(sg));
    }

    // signature_algorithms — TLS 1.2+.
    if (negotiated >= ProtocolVersion::TLSv1_2 && !policy.signatureAlgorithms.empty())
    {
        SignatureAlgorithms sa;
        for (auto s : policy.signatureAlgorithms)
            sa.addScheme(s);
        extensions.add(std::move(sa));
    }

    // key_share / ECDHE.
    if (negotiated >= ProtocolVersion::TLSv1_3)
    {
        casket::ThrowIfFalse(!filteredGroups.empty(), "no common groups for key_share");

        const auto group = filteredGroups.front();
        ephemeralPrivateKey_ = crypto::GroupParams::generateKeyByParams(group);
        sharedGroupParams_ = group;
        const snet::crypto::GroupParams groups[] = {group};

        KeyShare keyShare(groups);
        keyShare.setPublicKey(0, ephemeralPrivateKey_);
        extensions.add(std::move(keyShare));
    }
    else if (negotiated > ProtocolVersion::SSLv3_0 && !filteredGroups.empty())
    {
        sharedGroupParams_ = filteredGroups.front();
        ephemeralPrivateKey_ = crypto::GroupParams::generateKeyByParams(sharedGroupParams_);
    }

    // TLS 1.0-1.2 flags.
    if (negotiated >= ProtocolVersion::TLSv1_0 && policy.useEncryptThenMac)
        extensions.add(EncryptThenMAC());

    if (negotiated >= ProtocolVersion::TLSv1_0 && policy.useExtendedMasterSecret)
        extensions.add(ExtendedMasterSecret());

    if (negotiated >= ProtocolVersion::TLSv1_0 && !policy.alpn.empty())
        extensions.add(ALPN(policy.alpn));

    // Cipher suites: filter by supported.
    casket::ThrowIfFalse(!policy.suites.empty(), "no cipher suites");

    std::array<std::uint16_t, ClientHello::kMaxSuites> suitesBuf{};
    const std::size_t suitesCount = CipherSuiteManager::getInstance().filterSupported(policy.suites, suitesBuf);
    casket::ThrowIfFalse(suitesCount > 0, "no supported cipher suites");

    ClientHello ch{};
    ch.version = legacyVersion;
    ch.random = clientRandom_;
    ch.sessionID = policy.sessionId;
    ch.extensions = &extensions;

    std::array<std::uint8_t, 1> compressionMethods{0};
    ch.compMethods = {compressionMethods.data(), compressionMethods.size()};

    for (std::size_t i = 0; i < suitesCount; ++i)
    {
        casket::ThrowIfFalse(ch.suites.push_back(suitesBuf[i]), "cipher suite list overflow");
    }

    ch.suites.push_back(casket::make_uint16(0x00, 0xFF));

    record->serializeHandshake(HandshakeMessage(std::move(ch)), 0, *this);
    casket::ThrowIfFalse(addOutgoingRecord(0, record.get()), "outgoing records overflow");
    record.release();
}

void Session::processServerHello(const ServerHello& serverHello)
{
    assert(serverHello.random.size() == TLS_RANDOM_SIZE);
    std::copy_n(serverHello.random.data(), TLS_RANDOM_SIZE, serverRandom_.data());

    if (!serverHello.extensionsData.empty())
    {
        auto type =
            serverHello.isHelloRetryRequest ? HandshakeType::HelloRetryRequestCode : HandshakeType::ServerHelloCode;
        serverExtensions_.deserialize(Side::Server, serverHello.extensionsData, type);

        if (serverExtensions_.has(tls::ExtensionCode::SupportedVersions))
        {
            auto ext = serverExtensions_.get<tls::SupportedVersions>();
            metaInfo_.version = std::move(ext->versions()[0]);
        }

        if (serverExtensions_.has(tls::ExtensionCode::EncryptThenMac))
        {
            recordLayer_.enableEncryptThenMAC();
        }

        if (serverExtensions_.has(tls::ExtensionCode::ExtendedMasterSecret))
        {
            flags_.set(SessionBit::UseExtendedMasterSecret);
        }
    }

    metaInfo_.cipherSuite = CipherSuiteManager::getInstance().getCipherSuiteById(serverHello.cipherSuite);
    casket::ThrowIfFalse(metaInfo_.cipherSuite, "Cipher suite not found");

    if (!flags_.test(SessionBit::Monitor))
    {
        recordLayer_.setVersion(metaInfo_.version);
        fetchAlgorithms();

        if (metaInfo_.version == tls::ProtocolVersion::TLSv1_3 && ephemeralPrivateKey_)
        {
            if (peerPublicKey_)
            {
                /// We know public key by external way
                generateHandshakeSecret(peerPublicKey_, ephemeralPrivateKey_);
            }
            else
            {
                /// We know public key by key share
                auto keyShare = serverExtensions_.get<KeyShare>();
                generateHandshakeSecret(keyShare->getPublicKey(), ephemeralPrivateKey_);
            }
        }
    }
}

void Session::constructServerHello(const ServerHelloPolicy& policy)
{
    auto record = recordPool_.acquireScoped();
    casket::ThrowIfFalse(record.get() != nullptr, "record pool exhausted");

    // Protocol version: the policy already picked one.
    casket::ThrowIfFalse(policy.version != ProtocolVersion(), "policy: version not set");
    metaInfo_.version = policy.version;
    const ProtocolVersion legacyVersion =
        policy.version >= ProtocolVersion::TLSv1_3 ? ProtocolVersion::TLSv1_2 : policy.version;

    // Cipher suite configuraion.
    casket::ThrowIfFalse(policy.suite != 0, "policy: cipher suite not set");
    metaInfo_.cipherSuite = CipherSuiteManager::getInstance().getCipherSuiteById(policy.suite);
    casket::ThrowIfFalse(metaInfo_.cipherSuite != nullptr, "unknown cipher suite 0x{:04x}", policy.suite);

    Rand::generate(serverRandom_);

    Extensions extensions;
    extensions.reserve(6);

    // legacy_session_id_echo (TLS 1.3) / session_id (TLS 1.2-).
    nonstd::span<const std::uint8_t> sessionId;

    if (policy.version >= ProtocolVersion::TLSv1_3)
    {
        // RFC 8446 §4.1.3: echo legacy_session_id from ClientHello.
        sessionId = policy.sessionId;
    }
    else
    {
        // TLS 1.0-1.2: session_id is the session ID (for resumption).
        // Empty for a full handshake, non-empty for resumption.
        sessionId = policy.sessionId;
    }

    // TLS 1.0-1.2 echo extensions.
    if (policy.version < ProtocolVersion::TLSv1_3)
    {
        if (policy.useExtendedMasterSecret)
        {
            extensions.add(ExtendedMasterSecret());
            flags_.set(SessionBit::UseExtendedMasterSecret);
        }

        if (policy.useEncryptThenMac)
        {
            extensions.add(EncryptThenMAC());
            recordLayer_.enableEncryptThenMAC();
        }

        // RFC 5746: if the client offered renegotiation_info (or SCSV),
        // the server must include an empty renegotiation_info.
        if (policy.useRenegotiationInfo)
        {
            extensions.add(RenegotiationExtension());
        }
    }

    // TLS 1.3: supported_versions and key_share.
    if (policy.version >= ProtocolVersion::TLSv1_3)
    {
        // supported_versions is mandatory (RFC 8446 §4.2.1).
        SupportedVersions sv;
        sv.addVersion(policy.version);
        extensions.add(std::move(sv));

        casket::ThrowIfFalse(policy.group != crypto::GroupParams::NONE, "policy: key_share group not set");

        auto* clientKeyShare = clientExtensions_.get<KeyShare>();
        casket::ThrowIfFalse(clientKeyShare != nullptr, "TLS 1.3 ClientHello missing key_share");

        // Client's public key for the selected group.
        auto peerKey = clientKeyShare->getPublicKey(0);
        casket::ThrowIfFalse(peerKey, "key_share: no entry for selected group {}", policy.group.wireCode());

        // Generate the server's ephemeral key for the same group.
        auto serverEphKey = crypto::GroupParams::generateKeyByParams(policy.group);

        // Build a new KeyShare with exactly one entry (RFC 8446 §4.2.8).
        KeyShare serverKeyShare(policy.group, serverEphKey);

        // Persist session state.
        peerPublicKey_ = std::move(peerKey);
        ephemeralPrivateKey_ = std::move(serverEphKey);
        sharedGroupParams_ = policy.group;

        extensions.add(ExtensionVariant(std::move(serverKeyShare)));
    }

    // Resolve ciphers/hashes BEFORE generateHandshakeSecret(), which depends on handshakeHashAlg_.
    recordLayer_.setVersion(metaInfo_.version);
    fetchAlgorithms();

    // TLS 1.3: derive the handshake secret from ECDHE.
    // NOTE: peerPublicKey_ is the CLIENT's public key.
    if (!flags_.test(SessionBit::Monitor) && policy.version >= ProtocolVersion::TLSv1_3)
    {
        casket::ThrowIfFalse(ephemeralPrivateKey_ != nullptr, "no ephemeral private key");
        casket::ThrowIfFalse(peerPublicKey_ != nullptr, "no peer public key");
        generateHandshakeSecret(peerPublicKey_.get(), ephemeralPrivateKey_.get());
    }

    ServerHello sh{};
    sh.version = legacyVersion;
    sh.random = serverRandom_;
    sh.cipherSuite = policy.suite;
    sh.compMethod = 0;
    sh.sessionID = sessionId;
    sh.extensions = &extensions;

    record->serializeHandshake(HandshakeMessage(std::move(sh)), /*sideIndex=*/1, *this);
    casket::ThrowIfFalse(addOutgoingRecord(1, record.get()), "outgoing records overflow");
    record.release();
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

        record->serializeHandshake(HandshakeMessage(std::move(certificate)), sideIndex, *this);
    }
    else
    {
        TLSv1Certificate message;
        TLSv1Certificate::Entry entry;

        entry.cert = sideIndex == 0 ? clientCert_.get() : serverCert_.get();

        message.entryList[0] = std::move(entry);
        message.entryCount = 1;

        certificate.message = std::move(message);

        record->serializeHandshake(HandshakeMessage(std::move(certificate)), sideIndex, *this);
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

        record->serializeHandshake(HandshakeMessage(std::move(certVerify)), sideIndex, *this);
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
        std::vector<crypto::GroupParams> ecGroups;

        supportedGroupsByPeer->getEcGroups(ecGroups);
        sharedGroupParams_ = ChooseKeyExchangeGroup(ecGroups, {});
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
        crypto::SignatureScheme scheme{};

        const SignatureAlgorithms* peerSigAlgs = clientExtensions_.get<SignatureAlgorithms>();
        if (peerSigAlgs)
        {
            auto peerSchemes = peerSigAlgs->supportedSchemes();
            scheme = ChooseSignatureScheme(serverKey_, SignatureScheme::supportedSchemes(), peerSchemes);
            casket::ThrowIfFalse(scheme.isSet(), "no suitable signature scheme");
        }
        else
        {
            casket::ThrowIfTrue(metaInfo_.version >= ProtocolVersion::TLSv1_3,
                                "TLS 1.3 requires signature_algorithms extension");
        }

        if (metaInfo_.version == ProtocolVersion::TLSv1_2)
        {
            keyExchange.scheme = scheme;
        }

        auto hash = resolveSignatureHash(scheme, metaInfo_, serverKey_);
        keyExchange.signature = Signature::signMessage(
            hashCtx_, scheme.getKeyAlgorithm(), hash, serverKey_, signatureBuffer, {tbsBuffer.data(), tbsLength});
    }

    record->serializeHandshake(HandshakeMessage(std::move(keyExchange)), sideIndex, *this);
}

void Session::constructServerHelloDone(const int8_t sideIndex, Record* record)
{
    record->serializeHandshake(HandshakeMessage(ServerHelloDone()), sideIndex, *this);
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
        Signature::verifyMessage(
            hashCtx_, certVerify.scheme.getKeyAlgorithm(), hash, publicKey, certVerify.signature, handshakeBuffer_);
    }
}

void Session::processEncryptedExtensions(const EncryptedExtensions& encryptedExtensions)
{
    serverEncExtensions_.deserialize(
        Side::Server, encryptedExtensions.extensions, HandshakeType::EncryptedExtensionsCode);
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
        auto publicKey = Cert::publicKey(serverCert_);
        auto scheme = keyExchange.scheme;
        auto signature = keyExchange.signature;
        auto hash = resolveSignatureHash(scheme, metaInfo_, publicKey);

        std::vector<uint8_t> tbs;
        tbs.reserve(2 * TLS_RANDOM_SIZE + keyExchange.data.size());

        tbs.insert(tbs.end(), clientRandom_.begin(), clientRandom_.end());
        tbs.insert(tbs.end(), serverRandom_.begin(), serverRandom_.end());
        tbs.insert(tbs.end(), keyExchange.data.begin(), keyExchange.data.end());

        HashTraits::resetContext(hashCtx_);
        Signature::verifyMessage(hashCtx_, scheme.getKeyAlgorithm(), hash, publicKey, signature, tbs);
    }
}

void Session::processClientKeyExchange(const ClientKeyExchange& keyExchange)
{
    if (flags_.test(SessionBit::Monitor) || !keyInfo_.masterSecret.empty())
    {
        return;
    }

    if (std::holds_alternative<ClientEcdhPublic>(keyExchange.params))
    {
        const auto& params = std::get<ClientEcdhPublic>(keyExchange.params);
        KeyPtr publicKey = GroupParams::generateParams(sharedGroupParams_);
        AsymmKey::setEncodedPublicKey(publicKey, params.ecdhPublic);
        peerPublicKey_ = std::move(publicKey);
        PMS_ = GroupParams::deriveSecret(ephemeralPrivateKey_, peerPublicKey_, false);
    }
    else if (std::holds_alternative<EncryptedPreMasterSecret>(keyExchange.params))
    {
        const auto& msg = std::get<EncryptedPreMasterSecret>(keyExchange.params);

        auto ctx = crypto::CryptoManager::getInstance().createKeyContext(serverKey_);
        crypto::ThrowIfFalse(ctx != nullptr);

        crypto::ThrowIfFalse(0 < EVP_PKEY_decrypt_init(ctx));

#if (OPENSSL_VERSION_NUMBER >= 0x30000000L)

        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_WITH_TLS_PADDING));

        OSSL_PARAM params[2];
        unsigned int value = metaInfo_.version.code();
        params[0] = OSSL_PARAM_construct_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, &value);
        params[1] = OSSL_PARAM_construct_end();

        crypto::ThrowIfFalse(0 < EVP_PKEY_CTX_set_params(ctx, params));

#else  /// ^(OPENSSL_VERSION_NUMBER >= 0x30000000L)
       /// @todo: support it.
#endif /// !(OPENSSL_VERSION_NUMBER >= 0x30000000L)

        size_t size{0};
        crypto::ThrowIfFalse(
            0 < EVP_PKEY_decrypt(ctx, nullptr, &size, msg.preMasterSecret.data(), msg.preMasterSecret.size()));

        std::vector<std::uint8_t> pms(size);
        crypto::ThrowIfFalse(
            0 < EVP_PKEY_decrypt(ctx, pms.data(), &size, msg.preMasterSecret.data(), msg.preMasterSecret.size()));
        pms.resize(size);

        setPremasterSecret(std::move(pms));
    }
}

void Session::constructClientKeyExchange(const int8_t sideIndex, Record* record)
{
    ClientKeyExchange keyExchange;

    auto kex = CipherSuiteGetKeyExchange(metaInfo_.cipherSuite);
    if (kex == NID_kx_ecdhe)
    {
        std::vector<uint8_t> publicKey;
        ephemeralPrivateKey_ = GroupParams::generateKeyByParams(sharedGroupParams_);
        publicKey = AsymmKey::getEncodedPublicKey(ephemeralPrivateKey_);

        auto& ecdh = keyExchange.params.emplace<ClientEcdhPublic>();
        ecdh.ecdhPublic = publicKey;
        PMS_ = GroupParams::deriveSecret(ephemeralPrivateKey_, peerPublicKey_, false);
        record->serializeHandshake(HandshakeMessage(std::move(keyExchange)), sideIndex, *this);
    }
    else if (kex == NID_kx_rsa)
    {
        PMS_.resize(SSL_MAX_MASTER_KEY_LENGTH);
        auto pms = nonstd::span<uint8_t>(PMS_);

        uint16_t value = metaInfo_.version.code();
        pms[0] = casket::get_byte<0>(value);
        pms[1] = casket::get_byte<1>(value);

        Rand::generate(pms.subspan(2));

        auto serverKey = X509_get0_pubkey(serverCert_);

        auto ctx = crypto::CryptoManager::getInstance().createKeyContext(serverKey);
        crypto::ThrowIfFalse(ctx != nullptr);

        crypto::ThrowIfFalse(0 < EVP_PKEY_encrypt_init(ctx));
        size_t size{0};
        crypto::ThrowIfFalse(0 < EVP_PKEY_encrypt(ctx, nullptr, &size, PMS_.data(), PMS_.size()));

        std::vector<std::uint8_t> encryptedData(size);
        crypto::ThrowIfFalse(0 < EVP_PKEY_encrypt(ctx, encryptedData.data(), &size, PMS_.data(), PMS_.size()));
        encryptedData.resize(size);

        auto& params = keyExchange.params.emplace<EncryptedPreMasterSecret>();
        params.preMasterSecret = encryptedData;
        record->serializeHandshake(HandshakeMessage(std::move(keyExchange)), sideIndex, *this);
    }
}

nonstd::span<uint8_t> ComputeTLSv13FinishedMac(nonstd::span<const uint8_t> secret,
                                               nonstd::span<const uint8_t> transcriptHash,
                                               nonstd::span<uint8_t> sigBuffer, HashCtx* hashCtx,
                                               const MetaInfo& metaInfo)
{
    const auto& digest = CipherSuiteGetHandshakeDigest(metaInfo.cipherSuite);
    const auto digestName = HashTraits::getName(digest);

    crypto::SecureArray<uint8_t, TLS_MAX_MAC_LENGTH> finishedKey;
    size_t keySize = HashTraits::getSize(digest);

    crypto::DeriveFinishedKey(digestName, secret, {finishedKey.data(), keySize});

    crypto::KeyPtr hmacKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, finishedKey.data(), keySize));
    ThrowIfFalse(hmacKey);

    Signature::signInit(hashCtx, digest, hmacKey);
    Signature::signUpdate(hashCtx, transcriptHash);
    return Signature::signFinal(hashCtx, sigBuffer);
}

void Session::processFinished(const std::int8_t sideIndex, const Finished& finished)
{
    /// Check Finished data

    switch (metaInfo_.version.code())
    {
    case ProtocolVersion::TLSv1_3:
    {
        if (!keyInfo_.clientHndTrafficSecret.empty() || !keyInfo_.serverHndTrafficSecret.empty())
        {
            std::array<uint8_t, EVP_MAX_MD_SIZE> hashBuffer;
            auto transcriptHash = getTranscriptHash(hashBuffer);

            std::array<uint8_t, TLS_MAX_MAC_LENGTH> sigBuffer;
            const auto& secret = (sideIndex == 0 ? keyInfo_.clientHndTrafficSecret : keyInfo_.serverHndTrafficSecret);
            auto actual = ComputeTLSv13FinishedMac(secret, transcriptHash, sigBuffer, hashCtx_, metaInfo_);

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

            PRF(keyInfo_.masterSecret,
                (sideIndex == 0 ? "client finished" : "server finished"),
                transcriptHash,
                {},
                actual);

            casket::ThrowIfFalse(finished.verifyData.size() == actual.size() &&
                                     std::equal(finished.verifyData.begin(), finished.verifyData.end(), actual.begin()),
                                 "Bad Finished MAC");
        }
        break;
    }
    case ProtocolVersion::SSLv3_0:
    {
        if (keyInfo_.masterSecret.empty())
        {
            break;
        }

        std::array<uint8_t, crypto::kSsl3FinishedSize> actual{};
        crypto::ssl3FinishedMac(keyInfo_.masterSecret, handshakeBuffer_, sideIndex, actual);

        casket::ThrowIfFalse(finished.verifyData.size() == actual.size() &&
                                 std::equal(finished.verifyData.begin(), finished.verifyData.end(), actual.begin()),
                             "Bad Finished MAC (SSLv3)");
        break;
    }
    }
}

void Session::constructFinished(const int8_t sideIndex, Record* record)
{
    switch (metaInfo_.version.code())
    {
    case ProtocolVersion::TLSv1_3:
    {
        Finished finished;

        std::array<uint8_t, EVP_MAX_MD_SIZE> hashBuffer;
        auto transcriptHash = getTranscriptHash(hashBuffer);

        std::array<uint8_t, TLS_MAX_MAC_LENGTH> sigBuffer;
        const auto& secret = (sideIndex == 0 ? keyInfo_.clientHndTrafficSecret : keyInfo_.serverHndTrafficSecret);

        finished.verifyData = ComputeTLSv13FinishedMac(secret, transcriptHash, sigBuffer, hashCtx_, metaInfo_);

        record->serializeHandshake(HandshakeMessage(std::move(finished)), sideIndex, *this);
        break;
    }
    case ProtocolVersion::TLSv1_2:
    case ProtocolVersion::TLSv1_1:
    case ProtocolVersion::TLSv1_0:
    {
        Finished finished;

        std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
        auto transcriptHash = getTranscriptHash(buffer);

        std::array<uint8_t, TLS1_FINISH_MAC_LENGTH> actual;

        PRF(keyInfo_.masterSecret, (sideIndex == 0 ? "client finished" : "server finished"), transcriptHash, {}, actual);

        finished.verifyData = actual;

        record->serializeHandshake(HandshakeMessage(std::move(finished)), sideIndex, *this);
        break;
    }
    case ProtocolVersion::SSLv3_0:
    {
        if (keyInfo_.masterSecret.empty())
        {
            break;
        }

        Finished finished;
        std::array<uint8_t, crypto::kSsl3FinishedSize> mac{};
        crypto::ssl3FinishedMac(keyInfo_.masterSecret, handshakeBuffer_, sideIndex, mac);

        finished.verifyData = {mac.begin(), mac.end()};
        record->serializeHandshake(HandshakeMessage(std::move(finished)), sideIndex, *this);
        break;
    }
    }
}

void Session::processNewSessionTicket(const NewSessionTicket& sessionTicket)
{
    /// @todo: support it.
    (void)sessionTicket;
}

void Session::processKeyUpdate(const std::int8_t sideIndex, const KeyUpdate& keyUpdate)
{
    (void)keyUpdate;

    // RFC 8446, 4.6.3: rotate RECEIVING keys for the peer that sent KeyUpdate.
    // This is required in both normal and monitor modes — otherwise subsequent
    // records from this side cannot be decrypted.
    updateTrafficKeys(sideIndex);
}

void Session::constructKeyUpdate(const int8_t sideIndex, Record* record, bool requestUpdate)
{
    KeyUpdate keyUpdate(requestUpdate ? KeyUpdate::RequestUpdate::UpdateRequested
                                      : KeyUpdate::RequestUpdate::UpdateNotRequested);
    record->serializeHandshake(HandshakeMessage(std::move(keyUpdate)), sideIndex, *this);
}

void Session::sendKeyUpdate(const int8_t sideIndex, bool requestUpdate)
{
    Record* record = recordPool_.acquire();
    casket::ThrowIfTrue(record == nullptr, "record pool exhausted");
    record->setType(RecordType::Handshake);

    constructKeyUpdate(sideIndex, record, requestUpdate);
    encrypt(sideIndex, record);

    if (!outgoingRecords_.tryPush(record))
    {
        recordPool_.release(record);
        casket::ThrowIfTrue(false, "outgoingRecords_ overflow");
    }

    updateTrafficKeys(sideIndex);
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

void Session::updateTrafficKeys(const int8_t sideIndex)
{
    const auto digestName = HashTraits::getName(handshakeHashAlg_);

    auto& secret = (sideIndex == 0) ? keyInfo_.clientAppTrafficSecret : keyInfo_.serverAppTrafficSecret;
    auto& encKey = (sideIndex == 0) ? keyInfo_.clientEncKey : keyInfo_.serverEncKey;
    auto& iv = (sideIndex == 0) ? keyInfo_.clientIV : keyInfo_.serverIV;
    auto& cipherCtx = (sideIndex == 0) ? clientCipherCtx_ : serverCipherCtx_;

    crypto::UpdateTrafficSecret(digestName, secret);
    crypto::DeriveKey(digestName, secret, encKey);
    crypto::DeriveIV(digestName, secret, iv);

    if (sideIndex == 0)
    {
        seqnum_.resetClientSequence();
    }
    else
    {
        seqnum_.resetServerSequence();
    }
    recordLayer_.doTLSv13KeyUpdate(cipherCtx, encKey);
}

RecordPool::ScopedRecord Session::popOutgoingRecord() noexcept
{
    Record* record = nullptr;
    if (!outgoingRecords_.pop(record) || !record)
    {
        return {};
    }
    return RecordPool::ScopedRecord(record, &recordPool_);
}

bool Session::flushOne(IByteWriter& writer) noexcept
{
    if (!deferredRecord_)
    {
        deferredRecord_ = popOutgoingRecord();
        if (!deferredRecord_)
        {
            return false;
        }
    }

    std::array<std::uint8_t, TLS_HEADER_SIZE> header{};
    deferredRecord_->serializeHeader(header);

    const auto payload =
        deferredRecord_->isPlaintext() ? deferredRecord_->getPlaintext() : deferredRecord_->getCiphertext();

    if (writer.available() < header.size() + payload.size())
    {
        return false;
    }

    if (!writer.write(header) || !writer.write(payload))
    {
        return false;
    }

    deferredRecord_.release();
    return true;
}

std::size_t Session::flush(IByteWriter& writer) noexcept
{
    std::size_t n = 0;
    while (flushOne(writer))
    {
        ++n;
    }
    return n;
}

} // namespace snet::tls