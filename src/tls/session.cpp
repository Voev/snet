#include <cassert>
#include <array>
#include <limits>
#include <memory>

#include <casket/utils/exception.hpp>
#include <casket/utils/hexlify.hpp>

#include <snet/utils/print_hex.hpp>
#include <snet/utils/memory_viewer.hpp>

#include <snet/tls/session.hpp>
#include <snet/tls/record_decoder.hpp>
#include <snet/tls/prf.hpp>
#include <snet/crypto/exception.hpp>
#include <snet/tls/server_info.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

#include <snet/tls/record/cipher_traits.hpp>
#include <snet/tls/record/aead_cipher.hpp>

#include <snet/crypto/cipher_context.hpp>

using namespace casket::utils;

namespace snet::tls
{

Session::Session(RecordPool& recordPool)
    : recordPool_(recordPool)
    , cipherContext_(crypto::AllocateCipherCtx())
    , cipherState_(0)
    , canDecrypt_(0)
{
}

Session::~Session() noexcept
{
}

void Session::decrypt(const int8_t sideIndex, Record* record)
{
    auto version = (version_ != ProtocolVersion()) ? version_ : record->getVersion();

    if (crypto::CipherIsAEAD(cipherTraits_))
    {
        CipherOperation op;
        std::span<uint8_t> nonceImplicit;
        uint64_t seqnum;

        if (sideIndex == 0)
        {
            seqnum = seqnum_.getClientSequence();
            nonceImplicit = client.clientIV;
            op.key = client.clientEncKey.data();
            op.keyLength = client.clientEncKey.size();
        }
        else
        {
            seqnum = seqnum_.getServerSequence();
            nonceImplicit = server.serverIV;
            op.key = server.serverEncKey.data();
            op.keyLength = server.serverEncKey.size();
        }

        if (version == ProtocolVersion::TLSv1_3)
        {
            uint8_t aad[TLS13_AEAD_AAD_SIZE];
            uint8_t nonce[TLS13_AEAD_NONCE_SIZE];

            AeadCipher::decryptInit(cipherContext_, cipherTraits_);
            auto tagLength = crypto::GetTagLength(cipherContext_);
            auto nonceSize = crypto::GetIVLength(cipherContext_);

            memcpy(nonce, nonceImplicit.data(), sizeof(nonce));
            for (int i = 0; i < 8; i++)
            {
                nonce[TLS13_AEAD_NONCE_SIZE - 1 - i] ^= ((seqnum >> (i * 8)) & 0xFF);
            }

            uint16_t length = record->getLength() - TLS_HEADER_SIZE;
            aad[0] = static_cast<uint8_t>(record->getType());
            aad[1] = 0x03;
            aad[2] = 0x03;
            aad[3] = utils::get_byte<0>(length);
            aad[4] = utils::get_byte<1>(length);

            op.ciphertext = record->payloadBuffer.data() + TLS_HEADER_SIZE;
            op.ciphertextLength = length - tagLength;
            op.plaintext = record->decryptedBuffer.data();
            op.plaintextLength = length - tagLength;
            op.iv = nonce;
            op.ivLength = nonceSize;
            op.aad = aad;
            op.aadLength = sizeof(aad);
            op.tag = op.ciphertext + op.ciphertextLength;
            op.tagLength = tagLength;

            std::cout << "================================================" << std::endl;
            utils::printHex(std::cout, "Key", {op.key, op.keyLength});
            utils::printHex(std::cout, "AAD", {op.aad, op.aadLength});
            utils::printHex(std::cout, "Nonce", {op.iv, op.ivLength});
            utils::printHex(std::cout, "Tag", {op.tag, op.tagLength});
            std::cout << "================================================" << std::endl;

            AeadCipher::decrypt(cipherContext_, op);

            uint8_t lastByte = op.plaintext[op.plaintextLength - 1];
            ThrowIfTrue(lastByte < 20 || lastByte > 23, "TLS record type had unexpected value");

            record->type = static_cast<RecordType>(lastByte);
            record->decryptedLength = op.plaintextLength - 1;
            record->isDecrypted_ = true;
        }
        else
        {
            uint8_t aad[TLS12_AEAD_AAD_SIZE];
            std::vector<uint8_t> nonce;

            AeadCipher::decryptInit(cipherContext_, cipherTraits_);
            auto tagLength = crypto::GetTagLength(cipherContext_);
            auto nonceSize = crypto::GetIVLength(cipherContext_);
            auto nonceExplicitLength = nonceSize - clientIV_.size();
            auto nonceExplicit = std::span{record->payloadBuffer.data() + TLS_HEADER_SIZE, nonceExplicitLength};

            nonce.reserve(nonceSize);
            nonce.insert(nonce.end(), nonceImplicit.begin(), nonceImplicit.end());
            nonce.insert(nonce.end(), nonceExplicit.begin(), nonceExplicit.end());

            uint16_t length = record->getLength() - TLS_HEADER_SIZE - nonceExplicitLength - tagLength;
            utils::store_be(seqnum, &aad[0]);
            aad[8] = static_cast<uint8_t>(record->type);
            aad[9] = record->version.majorVersion();
            aad[10] = record->version.minorVersion();
            aad[11] = utils::get_byte<0>(length);
            aad[12] = utils::get_byte<1>(length);

            op.ciphertext = record->payloadBuffer.data() + TLS_HEADER_SIZE + nonceExplicitLength;
            op.ciphertextLength = length;
            op.plaintext = record->decryptedBuffer.data();
            op.plaintextLength = length;
            op.iv = nonce.data();
            op.ivLength = nonceSize;
            op.aad = aad;
            op.aadLength = sizeof(aad);
            op.tag = op.ciphertext + op.ciphertextLength;
            op.tagLength = tagLength;

            std::cout << "================================================" << std::endl;
            utils::printHex(std::cout, "Key", {op.key, op.keyLength});
            utils::printHex(std::cout, "AAD", {op.aad, op.aadLength});
            utils::printHex(std::cout, "Nonce", {op.iv, op.ivLength});
            utils::printHex(std::cout, "Tag", {op.tag, op.tagLength});
            std::cout << "================================================" << std::endl;

            AeadCipher::decrypt(cipherContext_, op);

            record->decryptedLength = length;
            record->isDecrypted_ = true;
        }

        if (sideIndex == 0)
        {
            seqnum_.clientAccept();
        }
        else
        {
            seqnum_.serverAccept();
        }
    }
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
        /// @todo
        // if (serverExtensions_.has(tls::ExtensionCode::ExtendedMasterSecret))
        {
            // auto sessionHash = handshakeHash_.final(cipherSuite_.getHnshDigestName());
            // PRF(derivedSecret, "extended master secret", sessionHash, {}, masterSecret);
        }
        // else
        {
            // PRF(derivedSecret, "master secret", clientRandom_, serverRandom_, masterSecret);
        }
        secrets_.setSecret(SecretNode::MasterSecret, masterSecret);
        utils::printHex(std::cout, "MS", masterSecret);
    }

    cipherTraits_ = CipherSuiteManager::getInstance().fetchCipher(cipherSuite_.getCipherName());

    size_t keySize = crypto::GetKeyLength(cipherTraits_);
    size_t ivSize = crypto::GetIVLengthWithinKeyBlock(cipherTraits_);

    if (cipherSuite_.isAEAD())
    {
        keyBlock.resize(keySize * 2 + ivSize * 2);
        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", serverRandom_, clientRandom_, keyBlock);

        utils::DataReader keyBlockReader("TLS AEAD KeyBlock", keyBlock);
        clientEncKey_ = keyBlockReader.get_fixed<uint8_t>(keySize);
        serverEncKey_ = keyBlockReader.get_fixed<uint8_t>(keySize);
        clientIV_ = keyBlockReader.get_fixed<uint8_t>(ivSize);
        serverIV_ = keyBlockReader.get_fixed<uint8_t>(ivSize);
        keyBlockReader.assert_done();

        std::cout << "================================================" << std::endl;
        utils::printHex(std::cout, "MasterKey", secrets_.getSecret(SecretNode::MasterSecret));
        utils::printHex(std::cout, "Client Write key", clientEncKey_);
        utils::printHex(std::cout, "Server Write key", serverEncKey_);
        utils::printHex(std::cout, "Client IV", clientIV_);
        utils::printHex(std::cout, "Server IV", serverIV_);
        std::cout << "================================================" << std::endl;

        if (sideIndex == 0)
        {
            canDecrypt_ |= 0x1;
        }
        else
        {
            canDecrypt_ |= 0x2;
        }
    }
    else
    {
        auto md = CipherSuiteManager::getInstance().fetchDigest(cipherSuite_.getDigestName());
        auto macSize = EVP_MD_get_size(md);

        keyBlock.resize(macSize * 2 + keySize * 2 + ivSize * 2);

        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", serverRandom_, clientRandom_, keyBlock);

        utils::DataReader keyBlockReader("TLS KeyBlock", keyBlock);
        clientMacKey_ = keyBlockReader.get_fixed<uint8_t>(macSize);
        serverMacKey_ = keyBlockReader.get_fixed<uint8_t>(macSize);
        clientEncKey_ = keyBlockReader.get_fixed<uint8_t>(keySize);
        serverEncKey_ = keyBlockReader.get_fixed<uint8_t>(keySize);
        clientIV_ = keyBlockReader.get_fixed<uint8_t>(ivSize);
        serverIV_ = keyBlockReader.get_fixed<uint8_t>(ivSize);
        keyBlockReader.assert_done();

        std::cout << "================================================" << std::endl;
        utils::printHex(std::cout, "MasterKey", secrets_.getSecret(SecretNode::MasterSecret));
        utils::printHex(std::cout, "Client MAC key", clientMacKey_);
        utils::printHex(std::cout, "Server MAC key", serverMacKey_);
        utils::printHex(std::cout, "Client Write key", clientEncKey_);
        utils::printHex(std::cout, "Server Write key", serverEncKey_);
        utils::printHex(std::cout, "Client IV", clientIV_);
        utils::printHex(std::cout, "Server IV", serverIV_);
        std::cout << "================================================" << std::endl;

        if (sideIndex == 0)
        {
            canDecrypt_ |= 0x1;
        }
        else
        {
            canDecrypt_ |= 0x2;
        }
    }
}

void Session::setCipherTraits(crypto::CipherPtr cipherTraits) noexcept
{
    cipherTraits_ = std::move(cipherTraits);
}

void Session::generateTLS13KeyMaterial()
{
    if (!secrets_.isValid(ProtocolVersion::TLSv1_3))
    {
        return;
    }

    cipherTraits_ = CipherSuiteManager::getInstance().fetchCipher(cipherSuite_.getCipherName());
    auto keySize = cipherSuite_.getKeyBits() / 8;
    const auto& digest = cipherSuite_.getHnshDigestName();

    const auto& chts = secrets_.getSecret(SecretNode::ClientHandshakeTrafficSecret);

    clientEncKey_ = DeriveSecret(digest, chts, "key", {}, keySize);
    clientIV_ = DeriveSecret(digest, chts, "iv", {}, 12);

    const auto& shts = secrets_.getSecret(SecretNode::ServerHandshakeTrafficSecret);

    serverEncKey_ = DeriveSecret(digest, shts, "key", {}, keySize);
    serverIV_ = DeriveSecret(digest, shts, "iv", {}, 12);

    std::cout << "================================================" << std::endl;
    utils::printHex(std::cout, "Client Handshake Write key", clientEncKey_);
    utils::printHex(std::cout, "Client Handshake IV", clientIV_);
    utils::printHex(std::cout, "Server Handshake Write key", serverEncKey_);
    utils::printHex(std::cout, "Server Handshake IV", serverIV_);
    std::cout << "================================================" << std::endl;

    canDecrypt_ |= 0x1 | 0x2;
}

void Session::processFinished(const std::int8_t sideIndex)
{
    if (version_ == tls::ProtocolVersion::TLSv1_3)
    {
        generateApplicationSecrets(sideIndex);

        if (sideIndex == 0)
        {
            seqnum_.resetClientSequence();
        }
        else
        {
            seqnum_.resetServerSequence();
        }
    }
}

void Session::processKeyUpdate(const std::int8_t sideIndex)
{
    const auto& digest = cipherSuite_.getHnshDigestName();
    auto md = CipherSuiteManager::getInstance().fetchDigest(digest);
    auto keySize = cipherSuite_.getKeyBits() / 8;

    if (sideIndex == 0)
    {
        const auto& secret = secrets_.getSecret(SecretNode::ClientApplicationTrafficSecret);
        auto newsecret = DeriveSecret(digest, secret, "traffic upd", {}, EVP_MD_get_size(md));

        clientEncKey_ = DeriveSecret(digest, newsecret, "key", {}, keySize);
        clientIV_ = DeriveSecret(digest, newsecret, "iv", {}, 12);
        secrets_.setSecret(SecretNode::ClientApplicationTrafficSecret, newsecret);
        seqnum_.resetClientSequence();
    }
    else
    {
        const auto& secret = getSecret(SecretNode::ServerApplicationTrafficSecret);
        auto newsecret = DeriveSecret(digest, secret, "traffic upd", {}, EVP_MD_get_size(md));
        serverEncKey_ = DeriveSecret(digest, newsecret, "key", {}, keySize);
        serverIV_ = DeriveSecret(digest, newsecret, "iv", {}, 12);
        secrets_.setSecret(SecretNode::ServerApplicationTrafficSecret, newsecret);
        seqnum_.resetServerSequence();
    }
}

void Session::PRF(const Secret& secret, std::string_view usage, std::span<const uint8_t> rnd1,
                  std::span<const uint8_t> rnd2, std::span<uint8_t> out)
{
    ThrowIfFalse(version_ <= tls::ProtocolVersion::TLSv1_2, "Invalid TLS version");

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

void Session::updateHash(const int8_t sideIndex, std::span<const uint8_t> message)
{
    if (sideIndex == 0)
    {
        client.hash.update(message);
    }
    else
    {
        server.hash.update(message);
    }
}

void Session::setClientRandom(ClientRandom random)
{
    clientRandom_ = std::move(random);
}

const ClientRandom& Session::getClientRandom() const noexcept
{
    return clientRandom_;
}

void Session::setServerRandom(ServerRandom random)
{
    serverRandom_ = std::move(random);
}

void Session::setVersion(ProtocolVersion version)
{
    version_ = std::move(version);
}

const ProtocolVersion& Session::getVersion() const noexcept
{
    return version_;
}

void Session::setCipherSuite(const CipherSuite& cipherSuite)
{
    cipherSuite_ = cipherSuite;
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
    (void)pms;
    // derivedSecret = std::move(pms);
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

bool Session::canDecrypt(const int8_t sideIndex) const noexcept
{
    return ((canDecrypt_ & 0x1) && sideIndex == 0) || ((canDecrypt_ & 0x2) && sideIndex == 1);
}

void Session::setCipherState(const int8_t sideIndex) noexcept
{
    if (sideIndex == 0)
    {
        cipherState_ |= 0x1;
    }
    else
    {
        cipherState_ |= 0x2;
    }
}

bool Session::getCipherState(const int8_t sideIndex) const noexcept
{
    return ((cipherState_ & 0x1) && sideIndex == 0) || ((cipherState_ & 0x2) && sideIndex == 1);
}

void Session::generateHandshakeSecrets(const int8_t sideIndex, std::span<const uint8_t> dheSecret)
{
    const auto keySize = cipherSuite_.getKeyBits() / 8;
    const auto& digest = cipherSuite_.getHnshDigestName();

    auto md = CipherSuiteManager::getInstance().fetchDigest(digest);
    const size_t derivedKeySize = EVP_MD_get_size(md);

    if (sideIndex == 0)
    {
        client.earlySecret = HkdfExtract(digest, {}, {}, derivedKeySize);

        auto derivedEarlySecret = DeriveSecret(digest, client.earlySecret, "derived", {}, derivedKeySize);
        auto transcriptHash = client.hash.final(digest);

        client.derivedSecret = HkdfExtract(digest, client.earlySecret, dheSecret, derivedKeySize);

        client.clientTrafficKey =
            DeriveSecret(digest, client.derivedSecret, "c hs traffic", transcriptHash, derivedKeySize);
        client.clientEncKey = DeriveSecret(digest, client.clientTrafficKey, "key", {}, keySize);
        client.clientIV = DeriveSecret(digest, client.clientTrafficKey, "iv", {}, 12);

        client.serverTrafficKey =
            DeriveSecret(digest, client.derivedSecret, "s hs traffic", transcriptHash, derivedKeySize);
        client.serverEncKey = DeriveSecret(digest, client.serverTrafficKey, "key", {}, keySize);
        client.serverIV = DeriveSecret(digest, client.serverTrafficKey, "iv", {}, 12);

        std::cout << "================================================" << std::endl;
        utils::printHex(std::cout, "Client Handshake Write key", client.clientEncKey);
        utils::printHex(std::cout, "Client Handshake IV", client.clientIV);
        utils::printHex(std::cout, "Server Handshake Write key", client.serverEncKey);
        utils::printHex(std::cout, "Server Handshake IV", client.serverIV);
        std::cout << "================================================" << std::endl;

        canDecrypt_ |= 0x1;
    }
    else
    {
        server.earlySecret = HkdfExtract(digest, {}, {}, derivedKeySize);

        auto derivedEarlySecret = DeriveSecret(digest, server.earlySecret, "derived", {}, derivedKeySize);
        auto transcriptHash = server.hash.final(digest);

        server.derivedSecret = HkdfExtract(digest, server.earlySecret, dheSecret, derivedKeySize);
        server.clientTrafficKey =
            DeriveSecret(digest, server.derivedSecret, "c hs traffic", transcriptHash, derivedKeySize);
        server.clientEncKey = DeriveSecret(digest, server.clientTrafficKey, "key", {}, keySize);
        server.clientIV = DeriveSecret(digest, server.clientTrafficKey, "iv", {}, 12);

        server.serverTrafficKey =
            DeriveSecret(digest, server.derivedSecret, "s hs traffic", transcriptHash, derivedKeySize);
        server.serverEncKey = DeriveSecret(digest, server.serverTrafficKey, "key", {}, keySize);
        server.serverIV = DeriveSecret(digest, server.serverTrafficKey, "iv", {}, 12);

        std::cout << "================================================" << std::endl;
        utils::printHex(std::cout, "Client Handshake Write key", server.clientEncKey);
        utils::printHex(std::cout, "Client Handshake IV", server.clientIV);
        utils::printHex(std::cout, "Server Handshake Write key", server.serverEncKey);
        utils::printHex(std::cout, "Server Handshake IV", server.serverIV);
        std::cout << "================================================" << std::endl;

        canDecrypt_ |= 0x2;
    }
}

void Session::generateApplicationSecrets(const int8_t sideIndex)
{
    const auto keySize = cipherSuite_.getKeyBits() / 8;
    const auto& digest = cipherSuite_.getHnshDigestName();

    auto md = CipherSuiteManager::getInstance().fetchDigest(digest);
    const size_t derivedKeySize = EVP_MD_get_size(md);

    if (sideIndex == 0)
    {
        auto transcriptHash = client.hash.final(digest);

        client.derivedSecret = HkdfExtract(digest, client.derivedSecret, {}, derivedKeySize);

        client.clientTrafficKey =
            DeriveSecret(digest, client.derivedSecret, "c ap traffic", transcriptHash, derivedKeySize);
        client.clientEncKey = DeriveSecret(digest, client.clientTrafficKey, "key", {}, keySize);
        client.clientIV = DeriveSecret(digest, client.clientTrafficKey, "iv", {}, 12);

        client.serverTrafficKey =
            DeriveSecret(digest, client.derivedSecret, "s ap traffic", transcriptHash, derivedKeySize);
        client.serverEncKey = DeriveSecret(digest, client.serverTrafficKey, "key", {}, keySize);
        client.serverIV = DeriveSecret(digest, client.serverTrafficKey, "iv", {}, 12);

        std::cout << "================================================" << std::endl;
        utils::printHex(std::cout, "Client Application Write key", client.clientEncKey);
        utils::printHex(std::cout, "Client Application IV", client.clientIV);
        utils::printHex(std::cout, "Server Application Write key", client.serverEncKey);
        utils::printHex(std::cout, "Server Application IV", client.serverIV);
        std::cout << "================================================" << std::endl;
    }
    else
    {
        auto transcriptHash = server.hash.final(digest);

        server.derivedSecret = HkdfExtract(digest, server.derivedSecret, {}, derivedKeySize);

        server.clientTrafficKey =
            DeriveSecret(digest, server.derivedSecret, "c ap traffic", transcriptHash, derivedKeySize);
        server.clientEncKey = DeriveSecret(digest, server.clientTrafficKey, "key", {}, keySize);
        server.clientIV = DeriveSecret(digest, server.clientTrafficKey, "iv", {}, 12);

        server.serverTrafficKey =
            DeriveSecret(digest, server.derivedSecret, "s ap traffic", transcriptHash, derivedKeySize);
        server.serverEncKey = DeriveSecret(digest, server.serverTrafficKey, "key", {}, keySize);
        server.serverIV = DeriveSecret(digest, server.serverTrafficKey, "iv", {}, 12);

        std::cout << "================================================" << std::endl;
        utils::printHex(std::cout, "Client Application Write key", server.clientEncKey);
        utils::printHex(std::cout, "Client Application IV", server.clientIV);
        utils::printHex(std::cout, "Server Application Write key", server.serverEncKey);
        utils::printHex(std::cout, "Server Application IV", server.serverIV);
        std::cout << "================================================" << std::endl;
    }
}



size_t Session::writeRecords(std::span<uint8_t> buffer)
{
    size_t totalWritten = 0;

    while (!writingRecords_.empty() && totalWritten < buffer.size())
    {
        Record* record = writingRecords_.front();

        auto tempBuffer = buffer.subspan(totalWritten);
        (void)tempBuffer;
        //auto serialized = record->serialize(tempBuffer);

        //totalWritten += serialized.size();
        recordPool_.release(record);
        writingRecords_.pop();
    }

    return totalWritten;
}

} // namespace snet::tls