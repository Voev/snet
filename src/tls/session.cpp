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

static inline int GetIvLengthWithinKeyBlock(const EVP_CIPHER* c)
{
    if (EVP_CIPHER_get_mode(c) == EVP_CIPH_GCM_MODE)
        return EVP_GCM_TLS_FIXED_IV_LEN;
    else if (EVP_CIPHER_get_mode(c) == EVP_CIPH_CCM_MODE)
        return EVP_CCM_TLS_FIXED_IV_LEN;
    else
        return EVP_CIPHER_get_iv_length(c);
}

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

bool Session::canDecrypt(bool client2server) const noexcept
{
    if (!cipherTraits_)
    {
        return false;
    }
    return (client2server && !secrets_.getSecret(SecretNode::Type::ClientWriteKey).empty()) ||
           (!client2server && !secrets_.getSecret(SecretNode::Type::ServerWriteKey).empty());
}

void Session::decrypt(const int8_t sideIndex, Record& record)
{
    auto version = (version_ != ProtocolVersion()) ? version_ : record.version;

    if (crypto::CipherIsAEAD(cipherTraits_))
    {
        CipherOperation op;
        std::span<uint8_t> implicitIV;

        if (sideIndex == 0)
        {
            record.seqnum = seqnum_.getClientSequence();
            implicitIV = clientIV_;
            op.key = (uint8_t*)secrets_.getSecret(SecretNode::Type::ClientWriteKey).data();
            op.keyLength = secrets_.getSecret(SecretNode::Type::ClientWriteKey).size();
        }
        else
        {
            record.seqnum = seqnum_.getServerSequence();
            implicitIV = serverIV_;
            op.key = (uint8_t*)secrets_.getSecret(SecretNode::Type::ServerWriteKey).data();
            op.keyLength = secrets_.getSecret(SecretNode::Type::ServerWriteKey).size();
        }

        if (version == ProtocolVersion::TLSv1_3)
        {
            //
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
            nonce.insert(nonce.end(), clientIV_.begin(), clientIV_.end());
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

    auto cipher = CipherSuiteManager::getInstance().fetchCipher(cipherSuite_.getCipherName());

    size_t keySize = EVP_CIPHER_get_key_length(cipher);
    size_t ivSize = ::GetIvLengthWithinKeyBlock(cipher);

    if (cipherSuite_.isAEAD())
    {
        keyBlock.resize(keySize * 2 + ivSize * 2);
        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", serverRandom_, clientRandom_, keyBlock);

        utils::DataReader keyBlockReader("TLS AEAD KeyBlock", keyBlock);
        secrets_.setSecret(SecretNode::Type::ClientWriteKey, keyBlockReader.get_fixed<uint8_t>(keySize));
        secrets_.setSecret(SecretNode::Type::ServerWriteKey, keyBlockReader.get_fixed<uint8_t>(keySize));
        clientIV_ = keyBlockReader.get_fixed<uint8_t>(ivSize);
        serverIV_ = keyBlockReader.get_fixed<uint8_t>(ivSize);
        keyBlockReader.assert_done();

        utils::printHex(std::cout, "Client Write key", secrets_.getSecret(SecretNode::Type::ClientWriteKey));
        utils::printHex(std::cout, "Client IV", clientIV_);
        utils::printHex(std::cout, "Server Write key", secrets_.getSecret(SecretNode::Type::ServerWriteKey));
        utils::printHex(std::cout, "Server IV", serverIV_);

        cipherTraits_ = CipherSuiteManager::getInstance().fetchCipher(cipherSuite_.getCipherName());
    }
    else
    {
        auto md = CipherSuiteManager::getInstance().fetchDigest(cipherSuite_.getDigestName());
        auto macSize = EVP_MD_get_size(md);

        keyBlock.resize(macSize * 2 + keySize * 2 + ivSize * 2);

        utils::printHex(std::cout, "MasterKey", secrets_.getSecret(SecretNode::MasterSecret));

        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", serverRandom_, clientRandom_, keyBlock);

        utils::DataReader keyBlockReader("TLS KeyBlock", keyBlock);
        secrets_.setSecret(SecretNode::Type::ClientMacKey, keyBlockReader.get_fixed<uint8_t>(macSize));
        secrets_.setSecret(SecretNode::Type::ServerMacKey, keyBlockReader.get_fixed<uint8_t>(macSize));
        secrets_.setSecret(SecretNode::Type::ClientWriteKey, keyBlockReader.get_fixed<uint8_t>(keySize));
        secrets_.setSecret(SecretNode::Type::ServerWriteKey, keyBlockReader.get_fixed<uint8_t>(keySize));
        clientIV_ = keyBlockReader.get_fixed<uint8_t>(ivSize);
        serverIV_ = keyBlockReader.get_fixed<uint8_t>(ivSize);
        keyBlockReader.assert_done();

        utils::printHex(std::cout, "Client MAC key", secrets_.getSecret(SecretNode::Type::ClientMacKey));
        utils::printHex(std::cout, "Client Write key", secrets_.getSecret(SecretNode::Type::ClientWriteKey));
        utils::printHex(std::cout, "Client IV", clientIV_);
        utils::printHex(std::cout, "Server MAC key", secrets_.getSecret(SecretNode::Type::ServerMacKey));
        utils::printHex(std::cout, "Server Write key", secrets_.getSecret(SecretNode::Type::ServerWriteKey));
        utils::printHex(std::cout, "Server IV", serverIV_);

        cipherTraits_ = CipherSuiteManager::getInstance().fetchCipher(cipherSuite_.getCipherName());

        (void)sideIndex;

        /*if (sideIndex == 0)
        {
            clientToServer_.initDecrypt(cipherTraits_, clientWriteKey, clientIV);
            clientToServer_.setMacKey(clientMacKey);
        }
        else
        {
            serverToClient_.initDecrypt(cipherTraits_, serverWriteKey, serverIV);
            serverToClient_.setMacKey(serverMacKey);
        }*/
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

    utils::printHex(std::cout, "Server Handshake Write key", serverHandshakeWriteKey);
    utils::printHex(std::cout, "Server Handshake IV", serverHandshakeIV);

    utils::printHex(std::cout, "Client Handshake Write key", clientHandshakeWriteKey);
    utils::printHex(std::cout, "Client Handshake IV", clientHandshakeIV);

    // clientToServer_.initDecrypt(cipherTraits_, clientHandshakeWriteKey, clientHandshakeIV);
    // serverToClient_.initDecrypt(cipherTraits_, serverHandshakeWriteKey, serverHandshakeIV);
}

void Session::processFinished(const std::int8_t sideIndex)
{
    if (version_ == tls::ProtocolVersion::TLSv1_3)
    {
        auto keySize = cipherSuite_.getKeyBits() / 8;

        if (sideIndex == 0)
        {
            const auto& digest = cipherSuite_.getHnshDigestName();
            const auto& secret = getSecret(SecretNode::ClientTrafficSecret);

            auto clientWriteKey = hkdfExpandLabel(digest, secret, "key", {}, keySize);
            auto clientIV = hkdfExpandLabel(digest, secret, "iv", {}, 12);

            // clientToServer_.initDecrypt(cipherTraits_, clientWriteKey, clientIV);

            utils::printHex(std::cout, "Client Write key", clientWriteKey);
            utils::printHex(std::cout, "Client IV", clientIV);
        }
        else
        {
            const auto& digest = cipherSuite_.getHnshDigestName();
            const auto& secret = getSecret(SecretNode::ServerTrafficSecret);

            auto serverWriteKey = hkdfExpandLabel(digest, secret, "key", {}, keySize);
            auto serverIV = hkdfExpandLabel(digest, secret, "iv", {}, 12);

            // serverToClient_.initDecrypt(cipherTraits_, serverWriteKey, serverIV);

            utils::printHex(std::cout, "Server Write key", serverWriteKey);
            utils::printHex(std::cout, "Server IV", serverIV);
        }
    }
}

void Session::processKeyUpdate(const std::int8_t sideIndex)
{
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

        // clientToServer_.tls13UpdateKeys(newkey, newiv);
    }
    else
    {
        const auto& secret = getSecret(SecretNode::ServerTrafficSecret);
        auto newsecret = hkdfExpandLabel(digest, secret, "traffic upd", {}, EVP_MD_get_size(md));
        newkey = hkdfExpandLabel(digest, newsecret, "key", {}, keySize);
        newiv = hkdfExpandLabel(digest, newsecret, "iv", {}, 12);

        // serverToClient_.tls13UpdateKeys(newkey, newiv);
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

void Session::setCipherState() noexcept
{
    cipherState_ = true;
}

bool Session::getCipherState() const noexcept
{
    return cipherState_;
}

} // namespace snet::tls