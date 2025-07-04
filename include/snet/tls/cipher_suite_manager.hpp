/// @file
/// @brief Declaration of the cipher suite manager class.

#pragma once
#include <cstdint>
#include <vector>
#include <optional>
#include <string_view>
#include <memory>
#include <snet/tls/cipher_suite.hpp>

namespace snet::tls
{

/// @brief Manages the cipher suites for the TLS protocol.
class CipherSuiteManager final
{
private:
    /// @brief Default constructor.
    CipherSuiteManager();

    /// @brief Copy constructor.
    /// @param other Constant reference to the CipherSuiteManager.
    CipherSuiteManager(const CipherSuiteManager& other);

    /// @brief Move constructor.
    /// @param other rvalue reference to the CipherSuiteManager.
    CipherSuiteManager(CipherSuiteManager&& other) noexcept;

    /// @brief Copy assignment operator.
    /// @param other Constant reference to the CipherSuiteManager.
    /// @return Reference to the CipherSuiteManager.
    CipherSuiteManager& operator=(const CipherSuiteManager& other);

    /// @brief Move assignment operator.
    /// @param other rvalue reference to the CipherSuiteManager.
    /// @return Reference to the CipherSuiteManager.
    CipherSuiteManager& operator=(CipherSuiteManager&& other) noexcept;

public:
    /// @brief Gets the singleton instance of the CipherSuiteManager.
    /// @return Reference to the CipherSuiteManager instance.
    static CipherSuiteManager& getInstance();

    /// @brief Destructor.
    ~CipherSuiteManager() noexcept;

    /// @brief Gets a cipher suite by its ID.
    /// @param id The ID of the cipher suite.
    /// @return An optional containing the CipherSuite if found, otherwise std::nullopt.
    std::optional<CipherSuite> getCipherSuiteById(std::uint16_t id);

    /// @brief Gets a list of cipher suites.
    /// @param supported If true, returns only supported cipher suites. Defaults to true.
    /// @return A vector of CipherSuite objects.
    std::vector<CipherSuite> getCipherSuites(bool supported = true);

    /// @brief Sets the security level.
    /// @param securityLevel The security level to set.
    void setSecurityLevel(const int securityLevel);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::tls