/// @file
/// @brief Declaration of the CipherSuiteManager class.

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include <casket/nonstd/span.hpp>

#include <snet/tls/cipher_suite.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

/// @brief Metadata for a cipher suite: tag length in bytes.
struct CipherSuiteMeta
{
    int cipherTagLength{0};
};

/// @brief Manages TLS cipher suites and resolves them against the
///        OpenSSL configuration (cipher list, security level, versions).
///
/// Holds a single SSL_CTX and SSL for querying OpenSSL's cipher database.
/// Caches the list of supported cipher suites and invalidates the cache
/// when configuration changes (setVersion, setSecurityLevel).
///
/// @note Singleton; access via CipherSuiteManager::getInstance().
class CipherSuiteManager final
{
public:
    /// @brief Get the singleton instance.
    static CipherSuiteManager& getInstance();

    CipherSuiteManager(const CipherSuiteManager&)            = delete;
    CipherSuiteManager& operator=(const CipherSuiteManager&) = delete;

    ~CipherSuiteManager() noexcept;

    /// @brief Look up a cipher suite by its 16-bit wire ID.
    /// @param[in] id Cipher suite wire ID.
    /// @return Pointer to the SSL_CIPHER, or nullptr if unknown.
    const CipherSuite* getCipherSuiteById(std::uint16_t id);

    /// @brief Get all cipher suites (supported or full list).
    /// @param[in] supported If true, only suites supported by the current
    ///                      security level and cipher string.
    /// @return Vector of cipher suite pointers (owned by OpenSSL).
    std::vector<const CipherSuite*> getCipherSuites(bool supported = true);

    /// @brief Get the supported cipher suites via the cache.
    /// @return View into the internal cache; valid until the next
    ///         configuration change.
    nonstd::span<const CipherSuite*> getSupportedCipherSuites();

    /// @brief Restrict the SSL to a single protocol version.
    /// @param[in] version Protocol version to use.
    void setVersion(const ProtocolVersion& version);

    /// @brief Set the OpenSSL security level (0..5).
    /// @param[in] securityLevel Security level.
    void setSecurityLevel(int securityLevel);

    /// @brief Get the AEAD tag length for a cipher suite.
    /// @param[in] id Cipher suite wire ID.
    /// @return Tag length in bytes; 0 if unknown.
    int getTagLengthByID(std::uint16_t id);

    /// @brief Check whether a cipher suite is supported by the current
    ///        OpenSSL configuration (cipher list + security level).
    /// @param[in] id Cipher suite wire ID.
    /// @retval true  Supported.
    /// @retval false Unknown or filtered out.
    bool isSupported(std::uint16_t id);

    /// @brief Filter a list of cipher suite IDs by support.
    /// @param[in]  ids Candidate IDs, in preference order.
    /// @param[out] out Output buffer.
    /// @return Number of supported IDs written; 0 if none supported.
    std::size_t filterSupported(nonstd::span<const std::uint16_t> ids,
                                  nonstd::span<std::uint16_t> out);

private:
    CipherSuiteManager();

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace snet::tls