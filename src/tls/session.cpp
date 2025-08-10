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
#include <snet/crypto/cert.hpp>
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
    , cipherState_(0)
    , canDecrypt_(0)
    , monitor_(false)
    , debugKeys_(0)
{
}

void Session::reset() noexcept
{
    recordLayer_.reset();

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
            handshakeHash_.update(data);
            break;
        }
        case HandshakeType::ServerHelloCode:
        {
            casket::ThrowIfFalse(sideIndex == 1, "Incorrect side index");
            processServerHello(record->getHandshake<ServerHello>());
            handshakeHash_.update(data);
            break;
        }
        case HandshakeType::EncryptedExtensionsCode:
        {
            casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
            processEncryptedExtensions(record->getHandshake<EncryptedExtensions>());
            handshakeHash_.update(data);
            break;
        }
        case HandshakeType::ServerHelloDoneCode:
        {
            casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
            utils::DataReader reader("Server Hello Done", data.subspan(TLS_HANDSHAKE_HEADER_SIZE));
            reader.assert_done();
            handshakeHash_.update(data);
            break;
        }
        case HandshakeType::ServerKeyExchangeCode:
        {
            casket::ThrowIfFalse(sideIndex == 1, "Incorrect side index");
            processServerKeyExchange(record->getHandshake<ServerKeyExchange>());
            handshakeHash_.update(data);
            break;
        }
        case HandshakeType::ClientKeyExchangeCode:
        {
            processClientKeyExchange(sideIndex, data);
            break;
        }
        case HandshakeType::CertificateCode:
        {
            casket::ThrowIfFalse(sideIndex == 1, "Incorrect side index");
            processCertificate(record->getHandshake<Certificate>());
            handshakeHash_.update(data);
            break;
        }
        case HandshakeType::CertificateRequestCode:
            break;
        case HandshakeType::CertificateVerifyCode:
        {
            casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
            processCertificateVerify(record->getHandshake<CertificateVerify>());
            handshakeHash_.update(data);
            break;
        }
        case HandshakeType::FinishedCode:
        {
            processFinished(sideIndex, record->getHandshake<Finished>());

            if (metaInfo_.version == ProtocolVersion::TLSv1_3)
            {
                handshakeHash_.update(data);
            }
            else if (sideIndex == 0)
            {
                handshakeHash_.update(data);
            }
            break;
        }
        case HandshakeType::NewSessionTicketCode:
        {
            processSessionTicket(sideIndex, data);
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
                             clientEncKey_, clientMacKey_, clientIV_);
        seqnum_.acceptClientSequence();
    }
    else
    {
        recordLayer_.decrypt(serverCipherCtx_, hmacCtx_, hashCtx_, hmacHashAlg_, record, seqnum_.getServerSequence(),
                             serverEncKey_, serverMacKey_, serverIV_);
        seqnum_.acceptServerSequence();
    }
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
        if (serverExtensions_.has(tls::ExtensionCode::ExtendedMasterSecret))
        {
            std::array<uint8_t, EVP_MAX_MD_SIZE> digest;
            const auto sessionHash =
                handshakeHash_.final(hashCtx_, CipherSuiteGetHandshakeDigest(metaInfo_.cipherSuite), digest);

            PRF(PMS_, "extended master secret", sessionHash, {}, masterSecret);
        }
        else
        {
            PRF(PMS_, "master secret", clientRandom_, serverRandom_, masterSecret);
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

    if (CipherSuiteIsAEAD(metaInfo_.cipherSuite))
    {
        crypto::SecureArray<uint8_t, (EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH) * 2> keyBlockBuffer;
        size_t keyBlockSize = (keySize + ivSize) * 2;

        auto keyBlock = nonstd::span(keyBlockBuffer.data(), keyBlockSize);

        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", serverRandom_, clientRandom_, keyBlock);

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

        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", serverRandom_, clientRandom_, keyBlock);

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

    auto keySize = CipherSuiteGetKeySize(metaInfo_.cipherSuite);

    const auto& digest = CipherSuiteGetHandshakeDigest(metaInfo_.cipherSuite);
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
    assert(metaInfo_.version <= ProtocolVersion::TLSv1_2);

    std::string_view digest = EVP_MD_name(CipherSuiteGetHandshakeDigest(metaInfo_.cipherSuite));
    if (metaInfo_.version == ProtocolVersion::TLSv1_2 && digest == "MD5-SHA1")
    {
        return CipherSuiteGetHmacDigestName(metaInfo_.cipherSuite);
    }
    return digest;
}

void Session::PRF(const Secret& secret, std::string_view usage, nonstd::span<const uint8_t> rnd1,
                  nonstd::span<const uint8_t> rnd2, nonstd::span<uint8_t> out)
{
    casket::ThrowIfFalse(metaInfo_.version <= tls::ProtocolVersion::TLSv1_2, "Invalid TLS version");

    if (metaInfo_.version == tls::ProtocolVersion::SSLv3_0)
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
    return metaInfo_.version;
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

void Session::processClientHello(const ClientHello& clientHello)
{
    metaInfo_.version = clientHello.version;

    assert(clientHello.random.size() == TLS_RANDOM_SIZE);
    std::copy_n(clientHello.random.data(), TLS_RANDOM_SIZE, clientRandom_.data());

    if (metaInfo_.version != ProtocolVersion::SSLv3_0)
    {
        clientExtensions_.deserialize(Side::Client, clientHello.extensions);
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
        serverExtensions_.deserialize(Side::Server, serverHello.extensions);

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

void Session::processCertificate(const Certificate& certificate)
{
    if (std::holds_alternative<TLSv13Certificate>(certificate.message))
    {
        const auto& message = std::get<TLSv13Certificate>(certificate.message);
        serverCert_ = crypto::CertFromMemory(message.certList[0].data);
    }
    else if (std::holds_alternative<TLSv1Certificate>(certificate.message))
    {
        const auto& message = std::get<TLSv1Certificate>(certificate.message);
        serverCert_ = crypto::CertFromMemory(message.certList[0].data);
    }

    /// @todo verify certificate chain
}

/// @todo: use it
void Session::processCertificateRequest(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("Certificate Request", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));

    casket::ThrowIfTrue(reader.remaining_bytes() < 4, "Certificate_Req: Bad certificate request");

    const auto cert_type_codes = reader.get_span(1, 1, 255);
    const auto algs = reader.get_span(2, 2, 65534);

    casket::ThrowIfTrue(algs.size() % 2 != 0, "Bad length for signature IDs in certificate request");

    const uint16_t purported_size = reader.get_uint16_t();

    casket::ThrowIfTrue(reader.remaining_bytes() != purported_size, "Inconsistent length in certificate request");

    while (reader.has_remaining())
    {
        auto name_bits = reader.get_span(2, 0, 65535);
    }

    /// @todo: TLSv1.3 fix it.

    reader.assert_done();

    handshakeHash_.update(message);
}

void Session::processCertificateVerify(const CertificateVerify& certVerify)
{
    (void)certVerify;
    /// @todo: verify data.
}

void Session::processEncryptedExtensions(const EncryptedExtensions& encryptedExtensions)
{
    serverEncExtensions_.deserialize(Side::Server, encryptedExtensions.extensions);
}

void Session::processServerKeyExchange(const ServerKeyExchange& keyExchange)
{
    /// RFC 4492: section-5.4
    if (!keyExchange.signature.empty())
    {
        std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
        const Hash* hash;
        crypto::HashPtr fetchedHash;

        auto scheme = keyExchange.scheme;
        if (scheme.isSet())
        {
            fetchedHash = crypto::CryptoManager::getInstance().fetchDigest(scheme.getHashAlgorithm());
            hash = fetchedHash.get();
        }
        else
        {
            hash = CipherSuiteGetHandshakeDigest(metaInfo_.cipherSuite);
        }

        crypto::InitHash(hashCtx_, hash);
        crypto::UpdateHash(hashCtx_, clientRandom_);
        crypto::UpdateHash(hashCtx_, serverRandom_);
        crypto::UpdateHash(hashCtx_, keyExchange.data);

        auto digest = crypto::FinalHash(hashCtx_, buffer);
        auto publicKey = X509_get0_pubkey(serverCert_);

        crypto::VerifyDigest(hashCtx_, hash, publicKey, digest, keyExchange.signature);
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

    if (CipherSuiteGetKeyExchange(metaInfo_.cipherSuite) == NID_kx_rsa)
    {
        utils::DataReader reader("ClientKeyExchange", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        const auto encryptedPreMaster = reader.get_span(2, 0, 65535);
        reader.assert_done();

        crypto::KeyCtxPtr ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, getServerInfo().getServerKey(), nullptr));
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
    }
}

void Session::processFinished(const std::int8_t sideIndex, const Finished& finished)
{
    /// Check Finished data

    switch (metaInfo_.version.code())
    {
    case ProtocolVersion::TLSv1_3:
    {
        const auto& secret = (sideIndex == 0 ? secrets_.getSecret(SecretNode::ClientHandshakeTrafficSecret)
                                             : secrets_.getSecret(SecretNode::ServerHandshakeTrafficSecret));
        if (!secret.empty())
        {

            const auto& digest = CipherSuiteGetHandshakeDigest(metaInfo_.cipherSuite);
            const auto digestName = EVP_MD_name(digest);

            crypto::SecureArray<uint8_t, EVP_MAX_MD_SIZE> finishedKey;
            size_t keySize = EVP_MD_get_size(digest);

            DeriveFinishedKey(digestName, secret, {finishedKey.data(), keySize});

            crypto::KeyPtr hmacKey(EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, nullptr, finishedKey.data(), keySize));

            std::array<uint8_t, EVP_MAX_MD_SIZE> buffer;
            std::array<uint8_t, EVP_MAX_MD_SIZE> actual;
            size_t length = actual.size();
            const auto transcriptHash = handshakeHash_.final(hashCtx_, digest, buffer);

            crypto::ThrowIfFalse(0 < EVP_DigestSignInit(hashCtx_, nullptr, digest, nullptr, hmacKey));
            crypto::ThrowIfFalse(0 < EVP_DigestSignUpdate(hashCtx_, transcriptHash.data(), transcriptHash.size()));
            crypto::ThrowIfFalse(0 < EVP_DigestSignFinal(hashCtx_, actual.data(), &length));

            casket::ThrowIfFalse(finished.verifyData.size() == length &&
                                     std::equal(finished.verifyData.begin(), finished.verifyData.end(), actual.begin()),
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

            std::array<uint8_t, TLS1_FINISH_MAC_LENGTH> actual;
            tls1Prf(algorithm, key, (sideIndex == 0 ? "client finished" : "server finished"), transcriptHash, {},
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
            const auto& digest = CipherSuiteGetHandshakeDigest(metaInfo_.cipherSuite);
            const auto digestName = EVP_MD_name(digest);
            const auto& secret = secrets_.getSecret(SecretNode::ClientTrafficSecret);

            clientEncKey_.resize(CipherSuiteGetKeySize(metaInfo_.cipherSuite));
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
            std::string_view digestName = EVP_MD_name(CipherSuiteGetHandshakeDigest(metaInfo_.cipherSuite));
            const auto& secret = secrets_.getSecret(SecretNode::ServerTrafficSecret);

            serverEncKey_.resize(CipherSuiteGetKeySize(metaInfo_.cipherSuite));
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
    if (metaInfo_.version == ProtocolVersion::TLSv1_3)
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
    else if (metaInfo_.version == ProtocolVersion::TLSv1_2)
    {
        utils::DataReader reader("TLSv1.2 New Session Ticket", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
        casket::ThrowIfTrue(reader.remaining_bytes() < 6, "Session ticket message too short to be valid");
        reader.get_uint32_t();
        reader.get_span(2, 0, 65535);
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

    const auto& digest = CipherSuiteGetHandshakeDigest(metaInfo_.cipherSuite);
    std::string_view digestName = EVP_MD_name(digest);

    if (sideIndex == 0)
    {
        UpdateTrafficSecret(digestName, secrets_.get(SecretNode::ClientTrafficSecret));

        clientEncKey_.resize(CipherSuiteGetKeySize(metaInfo_.cipherSuite));
        clientIV_.resize(12);

        DeriveKey(digestName, secrets_.get(SecretNode::ClientTrafficSecret), clientEncKey_);
        DeriveIV(digestName, secrets_.get(SecretNode::ClientTrafficSecret), clientIV_);

        seqnum_.resetClientSequence();
    }
    else
    {
        UpdateTrafficSecret(digestName, secrets_.get(SecretNode::ServerTrafficSecret));

        serverEncKey_.resize(CipherSuiteGetKeySize(metaInfo_.cipherSuite));
        serverIV_.resize(12);

        DeriveKey(digestName, secrets_.get(SecretNode::ServerTrafficSecret), serverEncKey_);
        DeriveIV(digestName, secrets_.get(SecretNode::ServerTrafficSecret), serverIV_);

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
        cipherAlg_ = crypto::CryptoManager::getInstance().fetchCipher(cipherName);
        isAEAD = CipherIsAEAD(cipherAlg_);

        if (isAEAD)
        {
            recordLayer_.enableAEAD();
            recordLayer_.setTagLength(
                CipherSuiteManager::getInstance().getTagLengthByID(CipherSuiteGetID(metaInfo_.cipherSuite)));
        }
    }

    if (!isAEAD) // TLSv1.3 uses only AEAD, so don't check for version
    {
        hmacHashAlg_ =
            crypto::CryptoManager::getInstance().fetchDigest(CipherSuiteGetHmacDigestName(metaInfo_.cipherSuite));

        if (metaInfo_.version != ProtocolVersion::SSLv3_0)
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