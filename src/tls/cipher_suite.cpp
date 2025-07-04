#include <snet/tls/cipher_suite.hpp>

namespace snet::tls
{

CipherSuite::CipherSuite()
    : keySize_(0)
    , id_(0)
    , aead_(false)
{
}

CipherSuite::~CipherSuite() noexcept
{
}

CipherSuite::CipherSuite(std::uint16_t id, std::uint32_t keySize, std::string kexch, std::string auth,
                         std::string cipher, std::string digest, std::string hdigest,
                         std::string name, std::string version, bool aead)
    : cipher_(std::move(cipher))
    , digest_(std::move(digest))
    , hdigest_(std::move(hdigest))
    , kexch_(std::move(kexch))
    , auth_(std::move(auth))
    , name_(std::move(name))
    , version_(std::move(version))
    , keySize_(keySize)
    , id_(id)
    , aead_(aead)
{
}

std::uint16_t CipherSuite::getID() const
{
    return id_;
}

std::uint32_t CipherSuite::getKeySize() const
{
    return keySize_;
}

const std::string& CipherSuite::getCipherName() const
{
    return cipher_;
}

const std::string& CipherSuite::getDigestName() const
{
    return digest_;
}

const std::string& CipherSuite::getHnshDigestName() const
{
    return hdigest_;
}

const std::string& CipherSuite::getKeyExchName() const
{
    return kexch_;
}

const std::string& CipherSuite::getAuthName() const
{
    return auth_;
}

const std::string& CipherSuite::getSuiteName() const
{
    return name_;
}

const std::string& CipherSuite::getVersion() const
{
    return version_;
}

bool CipherSuite::isAEAD() const
{
    return aead_;
}

} // namespace snet::tls
