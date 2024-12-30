#pragma once
#include <cstdint>
#include <vector>
#include <optional>
#include <string_view>

#include <snet/tls/cipher_suite.hpp>

namespace snet::tls
{

class CipherSuiteManager final
{
private:
    CipherSuiteManager();

    CipherSuiteManager(const CipherSuiteManager& other);

    CipherSuiteManager(CipherSuiteManager&& other) noexcept;

    CipherSuiteManager& operator=(const CipherSuiteManager& other);

    CipherSuiteManager& operator=(CipherSuiteManager&& other) noexcept;

public:
    static CipherSuiteManager& getInstance();

    ~CipherSuiteManager() noexcept;

    std::optional<CipherSuite> getCipherSuiteById(std::uint16_t id);

    std::vector<CipherSuite> getCipherSuites(bool supported = true);

    EvpKdfPtr fetchKdf(std::string_view algorithm);

    EvpMacPtr fetchMac(std::string_view algorithm);

    EvpMdPtr fetchDigest(std::string_view algorithm);

    EvpCipherPtr fetchCipher(std::string_view algorithm);

    void setSecurityLevel(const int securityLevel);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::tls