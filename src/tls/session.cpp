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
#include <snet/tls/record/tls1_aead_cipher.hpp>

#include <snet/crypto/cipher_context.hpp>

using namespace casket::utils;

namespace snet::tls
{

Session::Session()
    : cipherContext_(crypto::AllocateCipherCtx())
    , cipherState_(false)
{
}

Session::~Session() noexcept
{
}

void Session::decrypt(const int8_t sideIndex, Record& record)
{
    auto version = (version_ != ProtocolVersion()) ? version_ : record.version;

    if (crypto::CipherIsAEAD(cipherTraits_))
    {
        CipherOperation op;
        std::span<uint8_t> nonceImplicit;

        if (sideIndex == 0)
        {
            record.seqnum = seqnum_.getClientSequence();
            nonceImplicit = clientIV_;
            op.key = clientEncKey_.data();
            op.keyLength = clientEncKey_.size();
        }
        else
        {
            record.seqnum = seqnum_.getServerSequence();
            nonceImplicit = serverIV_;
            op.key = serverEncKey_.data();
            op.keyLength = serverEncKey_.size();
        }

        if (version == ProtocolVersion::TLSv1_3)
        {
            uint8_t aad[TLS13_AEAD_AAD_SIZE];
            uint8_t nonce[TLS13_AEAD_NONCE_SIZE];

            v1::AeadCipher::decryptInit(cipherContext_, cipherTraits_);
            auto tagLength = crypto::GetTagLength(cipherContext_);
            auto nonceSize = crypto::GetIVLength(cipherContext_);

            memcpy(nonce, nonceImplicit.data(), sizeof(nonce));
            for (int i = 0; i < 8; i++)
            {
                nonce[TLS13_AEAD_NONCE_SIZE - 1 - i] ^= ((record.seqnum >> (i * 8)) & 0xFF);
            }

            uint16_t length = record.length - TLS_HEADER_SIZE;
            aad[0] = static_cast<uint8_t>(record.type);
            aad[1] = 0x03;
            aad[2] = 0x03;
            aad[3] = utils::get_byte<0>(length);
            aad[4] = utils::get_byte<1>(length);

            op.ciphertext = record.data + TLS_HEADER_SIZE;
            op.ciphertextLength = length - tagLength;
            op.plaintext = record.decrypted;
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

            v1::AeadCipher::decrypt(cipherContext_, op);

            uint8_t lastByte = op.plaintext[op.plaintextLength - 1];
            ThrowIfTrue(lastByte < 20 || lastByte > 23, "TLS record type had unexpected value");

            record.type = static_cast<RecordType>(lastByte);
            record.decryptedLength = op.plaintextLength - 1;
            record.is_decrypted = 1;
        }
        else
        {
            uint8_t aad[TLS12_AEAD_AAD_SIZE];
            std::vector<uint8_t> nonce;

            v1::AeadCipher::decryptInit(cipherContext_, cipherTraits_);
            auto tagLength = crypto::GetTagLength(cipherContext_);
            auto nonceSize = crypto::GetIVLength(cipherContext_);
            auto nonceExplicitLength = nonceSize - clientIV_.size();
            auto nonceExplicit = std::span{record.data + TLS_HEADER_SIZE, nonceExplicitLength};

            nonce.reserve(nonceSize);
            nonce.insert(nonce.end(), nonceImplicit.begin(), nonceImplicit.end());
            nonce.insert(nonce.end(), nonceExplicit.begin(), nonceExplicit.end());

            uint16_t length = record.length - TLS_HEADER_SIZE - nonceExplicitLength - tagLength;
            utils::store_be(record.seqnum, &aad[0]);
            aad[8] = static_cast<uint8_t>(record.type);
            aad[9] = record.version.majorVersion();
            aad[10] = record.version.minorVersion();
            aad[11] = utils::get_byte<0>(length);
            aad[12] = utils::get_byte<1>(length);

            op.ciphertext = record.data + TLS_HEADER_SIZE + nonceExplicitLength;
            op.ciphertextLength = length;
            op.plaintext = record.decrypted;
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

            v1::AeadCipher::decrypt(cipherContext_, op);

            record.decryptedLength = length;
            record.is_decrypted = 1;
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
        if (serverExtensions_.has(tls::ExtensionCode::ExtendedMasterSecret))
        {
            auto sessionHash = handshakeHash_.final(cipherSuite_.getHnshDigestName());
            PRF(PMS_, "extended master secret", sessionHash, {}, masterSecret);
        }
        else
        {
            PRF(PMS_, "master secret", clientRandom_, serverRandom_, masterSecret);
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

    clientEncKey_ = hkdfExpandLabel(digest, chts, "key", {}, keySize);
    clientIV_ = hkdfExpandLabel(digest, chts, "iv", {}, 12);

    const auto& shts = secrets_.getSecret(SecretNode::ServerHandshakeTrafficSecret);

    serverEncKey_ = hkdfExpandLabel(digest, shts, "key", {}, keySize);
    serverIV_ = hkdfExpandLabel(digest, shts, "iv", {}, 12);

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
        const auto keySize = cipherSuite_.getKeyBits() / 8;
        const auto& digest = cipherSuite_.getHnshDigestName();

        if (sideIndex == 0)
        {
            const auto& secret = getSecret(SecretNode::ClientApplicationTrafficSecret);

            clientEncKey_ = hkdfExpandLabel(digest, secret, "key", {}, keySize);
            clientIV_ = hkdfExpandLabel(digest, secret, "iv", {}, 12);

            seqnum_.resetClientSequence();

            std::cout << "================================================" << std::endl;
            utils::printHex(std::cout, "Client Write key", clientEncKey_);
            utils::printHex(std::cout, "Client IV", clientIV_);
            std::cout << "================================================" << std::endl;
        }
        else
        {
            const auto& secret = getSecret(SecretNode::ServerApplicationTrafficSecret);

            serverEncKey_ = hkdfExpandLabel(digest, secret, "key", {}, keySize);
            serverIV_ = hkdfExpandLabel(digest, secret, "iv", {}, 12);

            seqnum_.resetServerSequence();

            std::cout << "================================================" << std::endl;
            utils::printHex(std::cout, "Server Write key", serverEncKey_);
            utils::printHex(std::cout, "Server IV", serverIV_);
            std::cout << "================================================" << std::endl;
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
        auto newsecret = hkdfExpandLabel(digest, secret, "traffic upd", {}, EVP_MD_get_size(md));

        clientEncKey_ = hkdfExpandLabel(digest, newsecret, "key", {}, keySize);
        clientIV_ = hkdfExpandLabel(digest, newsecret, "iv", {}, 12);
        secrets_.setSecret(SecretNode::ClientApplicationTrafficSecret, newsecret);
        seqnum_.resetClientSequence();
    }
    else
    {
        const auto& secret = getSecret(SecretNode::ServerApplicationTrafficSecret);
        auto newsecret = hkdfExpandLabel(digest, secret, "traffic upd", {}, EVP_MD_get_size(md));
        serverEncKey_ = hkdfExpandLabel(digest, newsecret, "key", {}, keySize);
        serverIV_ = hkdfExpandLabel(digest, newsecret, "iv", {}, 12);
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

void Session::deserializeExtensions(utils::DataReader& reader, const Side side, const HandshakeType ht)
{
    if (side == Side::Client)
    {
        clientExtensions_.deserialize(reader, side, ht);
    }
    else if (side == Side::Server)
    {
        serverExtensions_.deserialize(reader, side, ht);
    }
}

const Extensions& Session::getExtensions(const Side side) const noexcept
{
    if (side == Side::Client)
    {
        return clientExtensions_;
    }
    else
    {
        return serverExtensions_;
    }
}

void Session::updateHash(std::span<const uint8_t> message)
{
    handshakeHash_.update(message);
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

void Session::setSessionID(std::vector<std::uint8_t> sessionID)
{
    sessionId_ = std::move(sessionID);
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

} // namespace snet::tls