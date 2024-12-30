#pragma once
#include <string>
#include <string_view>
#include <cstdint>

#include <snet/tls/types.hpp>

namespace snet::tls
{

class CipherSuite final
{
public:
    CipherSuite();

    ~CipherSuite() noexcept;

    explicit CipherSuite(std::uint16_t id, std::uint32_t bits, std::string kexch, std::string auth,
                         std::string cipher, std::string digest, std::string hdigest,
                         std::string name, std::string version, bool aead);

    std::uint16_t getID() const;

    std::uint32_t getKeyBits() const;

    const std::string& getSuiteName() const;

    const std::string& getCipherName() const;

    const std::string& getDigestName() const;

    const std::string& getHnshDigestName() const;

    const std::string& getKeyExchName() const;

    const std::string& getAuthName() const;

    const std::string& getVersion() const;

    bool isAEAD() const;

private:
    std::string cipher_;
    std::string digest_;
    std::string hdigest_;
    std::string kexch_;
    std::string auth_;
    std::string name_;
    std::string version_;
    std::uint32_t bits_; ///< Number of bits really used
    std::uint16_t id_;
    bool aead_;
};

} // namespace snet::tls