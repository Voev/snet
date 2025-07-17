#include <cassert>
#include <array>
#include <limits>
#include <memory>
#include <openssl/core_names.h>

#include <casket/utils/exception.hpp>
#include <casket/utils/hexlify.hpp>
#include <casket/log/color.hpp>
#include <casket/utils/string.hpp>

#include <snet/utils/print_hex.hpp>
#include <snet/utils/memory_viewer.hpp>

#include <snet/crypto/exception.hpp>
#include <snet/crypto/cipher_context.hpp>
#include <snet/crypto/hash_traits.hpp>
#include <snet/crypto/signature.hpp>
#include <snet/crypto/crypto_manager.hpp>

#include <snet/tls/session.hpp>
#include <snet/tls/record_decoder.hpp>
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
    , cipherSuite_(nullptr)
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

bool Session::canDecrypt(bool client2server) const noexcept
{
    return (client2server && clientToServer_.isInited()) || (!client2server && serverToClient_.isInited());
}

void Session::decrypt(const std::int8_t sideIndex, Record* record)
{
    auto version = (version_ != ProtocolVersion()) ? version_ : record->getVersion();
    auto input = record->getData();
    auto encryptThenMAC = handshake_.serverHello.extensions.has(ExtensionCode::EncryptThenMac);
    auto tagLength = CipherSuiteManager::getInstance().getTagLengthByID(CipherSuiteGetID(cipherSuite_));

    if (sideIndex == 0 && clientToServer_.isInited())
    {
        if (version == ProtocolVersion::TLSv1_3)
        {
            record->decryptedData = clientToServer_.tls13Decrypt(record->getType(), input.subspan(TLS_HEADER_SIZE),
                                                                 record->decryptedBuffer, tagLength);
        }
        else if (version <= ProtocolVersion::TLSv1_2)
        {
            record->decryptedData = clientToServer_.tls1Decrypt(
                hmacCtx_, hashCtx_, hmacHashAlg_, record->getType(), version, input.subspan(TLS_HEADER_SIZE),
                record->decryptedBuffer, tagLength, encryptThenMAC, CipherSuiteIsAEAD(cipherSuite_));
        }
    }
    else if (sideIndex == 1 && serverToClient_.isInited())
    {
        if (version == ProtocolVersion::TLSv1_3)
        {
            record->decryptedData = serverToClient_.tls13Decrypt(record->getType(), input.subspan(TLS_HEADER_SIZE),
                                                                 record->decryptedBuffer, tagLength);
        }
        else if (version <= ProtocolVersion::TLSv1_2)
        {
            int tagLength = CipherSuiteManager::getInstance().getTagLengthByID(CipherSuiteGetID(cipherSuite_));

            record->decryptedData = serverToClient_.tls1Decrypt(
                hmacCtx_, hashCtx_, hmacHashAlg_, record->getType(), version, input.subspan(TLS_HEADER_SIZE),
                record->decryptedBuffer, tagLength, encryptThenMAC, CipherSuiteIsAEAD(cipherSuite_));
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
            clientToServer_.init(cipherAlg_, clientWriteKey, clientIV);
            canDecrypt_ |= 1;
        }
        else
        {
            serverToClient_.init(cipherAlg_, serverWriteKey, serverIV);
            canDecrypt_ |= 2;
        }
    }
    else
    {
        auto macSize = EVP_MD_get_size(hmacHashAlg_);

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
            clientToServer_.init(cipherAlg_, clientWriteKey, clientIV, clientMacKey);
            canDecrypt_ |= 1;
        }
        else
        {
            serverToClient_.init(cipherAlg_, serverWriteKey, serverIV, serverMacKey);
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

    auto serverHandshakeWriteKey = hkdfExpandLabel(digestName, shts, "key", {}, keySize);
    auto serverHandshakeIV = hkdfExpandLabel(digestName, shts, "iv", {}, 12);

    const auto& chts = secrets_.getSecret(SecretNode::ClientHandshakeTrafficSecret);

    auto clientHandshakeWriteKey = hkdfExpandLabel(digestName, chts, "key", {}, keySize);
    auto clientHandshakeIV = hkdfExpandLabel(digestName, chts, "iv", {}, 12);

    if (debugKeys_)
    {
        utils::printHex(std::cout, serverHandshakeWriteKey, Colorize("Server Handshake Write key"));
        utils::printHex(std::cout, serverHandshakeIV, Colorize("Server Handshake IV"));
        utils::printHex(std::cout, clientHandshakeWriteKey, Colorize("Client Handshake Write key"));
        utils::printHex(std::cout, clientHandshakeIV, Colorize("Client Handshake IV"));
    }

    clientToServer_.init(cipherAlg_, clientHandshakeWriteKey, clientHandshakeIV);
    serverToClient_.init(cipherAlg_, serverHandshakeWriteKey, serverHandshakeIV);

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

void Session::processCertificateVerify(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");

    utils::DataReader reader("CertificateVerify", message.subspan(TLS_HANDSHAKE_HEADER_SIZE));
    reader.get_uint16_t();
    reader.get_range<uint8_t>(2, 0, 65535);
    reader.assert_done();

    handshakeHash_.update(message);
}

void Session::processEncryptedExtensions(const std::int8_t sideIndex, nonstd::span<const uint8_t> message)
{
    casket::ThrowIfTrue(sideIndex != 1, "Incorrect side index");
    handshake_.encryptedExtensions.deserialize(message.subspan((TLS_HANDSHAKE_HEADER_SIZE)));
}

/* Create a buffer containing data to be signed for server key exchange */
/*size_t construct_key_exchange_tbs(SSL_CONNECTION* s, unsigned char** ptbs, const void* param, size_t paramlen)
{
    size_t tbslen = 2 * SSL3_RANDOM_SIZE + paramlen;
    unsigned char* tbs = OPENSSL_malloc(tbslen);

    if (tbs == NULL)
    {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR, ERR_R_CRYPTO_LIB);
        return 0;
    }
    memcpy(tbs, s->s3.client_random, SSL3_RANDOM_SIZE);
    memcpy(tbs + SSL3_RANDOM_SIZE, s->s3.server_random, SSL3_RANDOM_SIZE);

    memcpy(tbs + SSL3_RANDOM_SIZE * 2, param, paramlen);

    *ptbs = tbs;
    return tbslen;
}*/

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

    /// @todo: serialize

    handshakeHash_.update(message);

    if (!getServerInfo().getServerKey())
    {
        return;
    }

    if (CipherSuiteGetKeyExchange(cipherSuite_) == NID_kx_rsa)
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

    if (!secrets_.getSecret(SecretNode::MasterSecret).empty())
    {
        if (version_ == ProtocolVersion::TLSv1_3) {}
        else if (version_ == ProtocolVersion::SSLv3_0) {}
        else
        {
            std::string_view algorithm = getHashAlgorithm();
            auto fecthedAlg = crypto::CryptoManager::getInstance().fetchDigest(algorithm);

            std::array<uint8_t, EVP_MAX_MD_SIZE> digest;
            const auto transcriptHash = handshakeHash_.final(hashCtx_, fecthedAlg, digest);
            const auto& key = secrets_.getSecret(SecretNode::MasterSecret);
            const auto& expect = (sideIndex == 0 ? handshake_.clientFinished.getVerifyData()
                                                 : handshake_.serverFinished.getVerifyData());

            std::array<uint8_t, TLS1_FINISH_MAC_LENGTH> actual;
            tls1Prf(algorithm, key, (sideIndex == 0 ? "client finished" : "server finished"), transcriptHash, {},
                    actual);

            casket::ThrowIfFalse(std::equal(expect.begin(), expect.end(), actual.begin()), "Bad Finished MAC");
        }
    }

    if (sideIndex == 0)
    {
        handshakeHash_.update(message);
    }

    if (version_ == tls::ProtocolVersion::TLSv1_3)
    {
        if (sideIndex == 0)
        {
            const auto& digest = CipherSuiteGetHandshakeDigest(cipherSuite_);
            const auto digestName = EVP_MD_name(digest);
            const auto& secret = getSecret(SecretNode::ClientTrafficSecret);

            auto clientWriteKey = hkdfExpandLabel(digestName, secret, "key", {}, CipherSuiteGetKeySize(cipherSuite_));
            auto clientIV = hkdfExpandLabel(digestName, secret, "iv", {}, 12);

            clientToServer_.init(cipherAlg_, clientWriteKey, clientIV);

            if (debugKeys_)
            {
                utils::printHex(std::cout, clientWriteKey, Colorize("Client Write key"));
                utils::printHex(std::cout, clientIV, Colorize("Client IV"));
            }
        }
        else
        {
            std::string_view digest = EVP_MD_name(CipherSuiteGetHandshakeDigest(cipherSuite_));
            const auto& secret = getSecret(SecretNode::ServerTrafficSecret);

            auto serverWriteKey = hkdfExpandLabel(digest, secret, "key", {}, CipherSuiteGetKeySize(cipherSuite_));
            auto serverIV = hkdfExpandLabel(digest, secret, "iv", {}, 12);

            serverToClient_.init(cipherAlg_, serverWriteKey, serverIV);

            if (debugKeys_)
            {
                utils::printHex(std::cout, serverWriteKey, Colorize("Server Write key"));
                utils::printHex(std::cout, serverIV, Colorize("Server IV"));
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
        reader.get_range<uint8_t>(2, 0, 65535);
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

    std::vector<uint8_t> newsecret;
    std::vector<uint8_t> newkey;
    std::vector<uint8_t> newiv;

    const auto& digest = CipherSuiteGetHandshakeDigest(cipherSuite_);
    std::string_view digestName = EVP_MD_name(digest);

    if (sideIndex == 0)
    {
        const auto& secret = getSecret(SecretNode::ClientTrafficSecret);
        auto newsecret = hkdfExpandLabel(digestName, secret, "traffic upd", {}, EVP_MD_size(digest));
        newkey = hkdfExpandLabel(digestName, newsecret, "key", {}, CipherSuiteGetKeySize(cipherSuite_));
        newiv = hkdfExpandLabel(digestName, newsecret, "iv", {}, 12);

        clientToServer_.tls13UpdateKeys(newkey, newiv);
    }
    else
    {
        const auto& secret = getSecret(SecretNode::ServerTrafficSecret);
        auto newsecret = hkdfExpandLabel(digestName, secret, "traffic upd", {}, EVP_MD_size(digest));
        newkey = hkdfExpandLabel(digestName, newsecret, "key", {}, CipherSuiteGetKeySize(cipherSuite_));
        newiv = hkdfExpandLabel(digestName, newsecret, "iv", {}, 12);

        serverToClient_.tls13UpdateKeys(newkey, newiv);
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