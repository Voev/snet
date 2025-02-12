#include <cassert>
#include <array>
#include <limits>
#include <memory>

#include <openssl/err.h>
#include <openssl/kdf.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/core_names.h>

#include <casket/utils/exception.hpp>
#include <casket/utils/hexlify.hpp>

#include <snet/utils/print_hex.hpp>
#include <snet/utils/memory_viewer.hpp>

#include <snet/tls/session.hpp>
#include <snet/tls/record_decoder.hpp>
#include <snet/tls/prf.hpp>
#include <snet/tls/exception.hpp>
#include <snet/tls/server_info.hpp>
#include <snet/tls/cipher_suite_manager.hpp>

using namespace casket::utils;

namespace snet::tls
{

Session::Session()
    : cipherState_(false)
{
}

const ClientRandom& Session::getClientRandom() const
{
    return clientRandom_;
}

void Session::setSecrets(const SecretNode& secrets)
{
    secrets_ = secrets;
}

void Session::setServerInfo(const ServerInfo& serverInfo)
{
    serverInfo_.setHostname(serverInfo.getHostname());
    serverInfo_.setIPAddress(serverInfo.getIPAddress());
    serverInfo_.setServerKey(serverInfo.getServerKey());
}

void Session::decrypt(const std::int8_t sideIndex, RecordType recordType,
                      ProtocolVersion recordVersion, std::span<const uint8_t> inputBytes,
                      std::vector<std::uint8_t>& outputBytes)
{
    auto version = (version_ != ProtocolVersion()) ? version_ : recordVersion;

    if (sideIndex == 0 && clientToServer_.isInited())
    {
        clientToServer_.decrypt(recordType, version, inputBytes, outputBytes,
                                serverExtensions_.has(ExtensionCode::EncryptThenMac));
    }
    else if (sideIndex == 1 && serverToClient_.isInited())
    {
        serverToClient_.decrypt(recordType, version, inputBytes, outputBytes,
                                serverExtensions_.has(ExtensionCode::EncryptThenMac));
    }
}

static int tls_iv_length_within_key_block(const EVP_CIPHER* c)
{
    /* If GCM/CCM mode only part of IV comes from PRF */
    if (EVP_CIPHER_get_mode(c) == EVP_CIPH_GCM_MODE)
        return EVP_GCM_TLS_FIXED_IV_LEN;
    else if (EVP_CIPHER_get_mode(c) == EVP_CIPH_CCM_MODE)
        return EVP_CCM_TLS_FIXED_IV_LEN;
    else
        return EVP_CIPHER_get_iv_length(c);
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
    size_t ivSize = tls_iv_length_within_key_block(cipher);

    if (cipherSuite_.isAEAD())
    {
        keyBlock.resize(keySize * 2 + ivSize * 2);
        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", serverRandom_,
            clientRandom_, keyBlock);

        utils::MemoryViewer viewer(keyBlock);
        auto clientWriteKey = viewer.view(keySize);
        auto serverWriteKey = viewer.view(keySize);
        auto clientIV = viewer.view(ivSize);
        auto serverIV = viewer.view(ivSize);

        if (sideIndex == 0)
        {
            clientToServer_.init(cipherSuite_, clientWriteKey, clientIV);
        }
        else
        {
            serverToClient_.init(cipherSuite_, serverWriteKey, serverIV);
        }
    }
    else
    {
        auto md = CipherSuiteManager::getInstance().fetchDigest(cipherSuite_.getDigestName());
        auto macSize = EVP_MD_get_size(md);

        keyBlock.resize(macSize * 2 + keySize * 2 + ivSize * 2);

        utils::printHex(std::cout, "MasterKey", secrets_.getSecret(SecretNode::MasterSecret));

        PRF(secrets_.getSecret(SecretNode::MasterSecret), "key expansion", serverRandom_,
            clientRandom_, keyBlock);

        utils::MemoryViewer viewer(keyBlock);
        auto clientMacKey = viewer.view(macSize);
        auto serverMacKey = viewer.view(macSize);
        auto clientWriteKey = viewer.view(keySize);
        auto serverWriteKey = viewer.view(keySize);
        auto clientIV = viewer.view(ivSize);
        auto serverIV = viewer.view(ivSize);

        utils::printHex(std::cout, "Client MAC key", clientMacKey);
        utils::printHex(std::cout, "Client Write key", clientWriteKey);
        utils::printHex(std::cout, "Client IV", clientIV);
        utils::printHex(std::cout, "Server MAC key", serverMacKey);
        utils::printHex(std::cout, "Server Write key", serverWriteKey);
        utils::printHex(std::cout, "Server IV", serverIV);

        if (sideIndex == 0)
        {
            clientToServer_.init(cipherSuite_, clientWriteKey, clientIV, clientMacKey);
        }
        else
        {
            serverToClient_.init(cipherSuite_, serverWriteKey, serverIV, serverMacKey);
        }
    }
    cipherState_ = true;
}

void Session::generateTLS13KeyMaterial()
{
    if (!secrets_.isValid(ProtocolVersion::TLSv1_3))
    {
        return;
    }

    auto keySize = cipherSuite_.getKeyBits() / 8;

    auto serverHandshakeWriteKey = hkdfExpandLabel(
        cipherSuite_.getHnshDigestName(),
        secrets_.getSecret(SecretNode::ServerHandshakeTrafficSecret), "key", {}, keySize);
    auto serverHandshakeIV =
        hkdfExpandLabel(cipherSuite_.getHnshDigestName(),
                        secrets_.getSecret(SecretNode::ServerHandshakeTrafficSecret), "iv", {}, 12);

    auto clientHandshakeWriteKey = hkdfExpandLabel(
        cipherSuite_.getHnshDigestName(),
        secrets_.getSecret(SecretNode::ClientHandshakeTrafficSecret), "key", {}, keySize);
    auto clientHandshakeIV =
        hkdfExpandLabel(cipherSuite_.getHnshDigestName(),
                        secrets_.getSecret(SecretNode::ClientHandshakeTrafficSecret), "iv", {}, 12);

    utils::printHex(std::cout, "Server Handshake Write key", serverHandshakeWriteKey);
    utils::printHex(std::cout, "Server Handshake IV", serverHandshakeIV);

    utils::printHex(std::cout, "Client Handshake Write key", clientHandshakeWriteKey);
    utils::printHex(std::cout, "Client Handshake IV", clientHandshakeIV);

    clientToServer_.init(cipherSuite_, clientHandshakeWriteKey, clientHandshakeIV);
    serverToClient_.init(cipherSuite_, serverHandshakeWriteKey, serverHandshakeIV);

    cipherState_ = true;
}

void Session::processFinished(const std::int8_t sideIndex)
{
    if (version_ == tls::ProtocolVersion::TLSv1_3)
    {
        auto keySize = cipherSuite_.getKeyBits() / 8;

        if (sideIndex == 0)
        {
            auto clientWriteKey =
                hkdfExpandLabel(cipherSuite_.getHnshDigestName(),
                                getSecret(SecretNode::ClientTrafficSecret), "key", {}, keySize);
            auto clientIV =
                hkdfExpandLabel(cipherSuite_.getHnshDigestName(),
                                getSecret(SecretNode::ClientTrafficSecret), "iv", {}, 12);

            clientToServer_.init(cipherSuite_, clientWriteKey, clientIV);

            utils::printHex(std::cout, "Client Write key", clientWriteKey);
            utils::printHex(std::cout, "Client IV", clientIV);
        }
        else
        {
            auto serverWriteKey =
                hkdfExpandLabel(cipherSuite_.getHnshDigestName(),
                                getSecret(SecretNode::ServerTrafficSecret), "key", {}, keySize);
            auto serverIV =
                hkdfExpandLabel(cipherSuite_.getHnshDigestName(),
                                getSecret(SecretNode::ServerTrafficSecret), "iv", {}, 12);

            serverToClient_.init(getCipherSuite(), serverWriteKey, serverIV);

            utils::printHex(std::cout, "Server Write key", serverWriteKey);
            utils::printHex(std::cout, "Server IV", serverIV);
        }
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

bool Session::canDecrypt(bool client2server) const noexcept
{
    return (client2server && clientToServer_.isInited()) ||
           (!client2server && serverToClient_.isInited());
}

const ProtocolVersion& Session::version() const
{
    return version_;
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

void Session::setClientRandom(const ClientRandom& random)
{
    clientRandom_ = random;
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

void Session::setCipherSuite(CipherSuite cipherSuite)
{
    cipherSuite_ = std::move(cipherSuite);
}

const CipherSuite& Session::getCipherSuite() const noexcept
{
    return cipherSuite_;
}

void Session::deserializeExtensions(utils::DataReader& reader, const Side side,
                                    const HandshakeType ht)
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

const Secret& Session::getSecret(const SecretNode::Type type) const
{
    return secrets_.getSecret(type);
}

void Session::updateKeys(const Side side, const std::vector<std::uint8_t>& key,
                         const std::vector<std::uint8_t>& iv)
{
    if (side == Side::Client)
    {
        clientToServer_.tls13UpdateKeys(key, iv);
    }
    else
    {
        serverToClient_.tls13UpdateKeys(key, iv);
    }
}

void Session::setPremasterSecret(std::vector<std::uint8_t> pms)
{
    PMS_ = std::move(pms);
}

const ServerInfo& Session::getServerInfo() const
{
    return serverInfo_;
}

void Session::cipherState(bool state)
{
    cipherState_ = state;
}

bool Session::cipherState() const
{
    return cipherState_;
}

} // namespace snet::tls