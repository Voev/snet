#pragma once
#include <string>
#include <string_view>
#include <cstdint>

#include <snet/tls/types.hpp>

namespace snet::tls
{

/// @brief Class representing a TLS cipher suite.
class CipherSuite final
{
public:
    /// @brief Default constructor.
    CipherSuite();

    /// @brief Destructor.
    ~CipherSuite() noexcept;

    /// @brief Copy constructor.
    /// @param other Constant reference to the cipher suite.
    CipherSuite(const CipherSuite& other) = default;

    /// @brief Move constructor.
    /// @param other rvalue reference to the cipher suite.
    CipherSuite(CipherSuite&& other) noexcept = default;

    /// @brief Copy assignment operator.
    /// @param other Constant reference to the cipher suite.
    CipherSuite& operator=(const CipherSuite& other) = default;

    /// @brief Move assignment operator.
    /// @param other rvalue reference to the cipher suite.
    CipherSuite& operator=(CipherSuite&& other) noexcept = default;

    /// @brief Constructor with parameters.
    /// @param id The cipher suite ID.
    /// @param bits The number of bits used.
    /// @param kexch The key exchange algorithm.
    /// @param auth The authentication algorithm.
    /// @param cipher The cipher algorithm.
    /// @param digest The digest algorithm.
    /// @param hdigest The handshake digest algorithm.
    /// @param name The name of the cipher suite.
    /// @param version The protocol version.
    /// @param aead Indicates if the cipher suite is AEAD.
    explicit CipherSuite(std::uint16_t id, std::uint32_t bits, std::string kexch, std::string auth,
                         std::string cipher, std::string digest, std::string hdigest,
                         std::string name, std::string version, bool aead);

    /// @brief Gets the cipher suite ID.
    /// @return The cipher suite ID.
    std::uint16_t getID() const;

    /// @brief Gets the number of bits used.
    /// @return The number of bits used.
    std::uint32_t getKeyBits() const;

    /// @brief Gets the name of the cipher suite.
    /// @return The name of the cipher suite.
    const std::string& getSuiteName() const;

    /// @brief Gets the name of the cipher algorithm.
    /// @return The name of the cipher algorithm.
    const std::string& getCipherName() const;

    /// @brief Gets the name of the digest algorithm.
    /// @return The name of the digest algorithm.
    const std::string& getDigestName() const;

    /// @brief Gets the name of the handshake digest algorithm.
    /// @return The name of the handshake digest algorithm.
    const std::string& getHnshDigestName() const;

    /// @brief Gets the name of the key exchange algorithm.
    /// @return The name of the key exchange algorithm.
    const std::string& getKeyExchName() const;

    /// @brief Gets the name of the authentication algorithm.
    /// @return The name of the authentication algorithm.
    const std::string& getAuthName() const;

    /// @brief Gets the protocol version.
    /// @return The protocol version.
    const std::string& getVersion() const;

    /// @brief Checks if the cipher suite is AEAD.
    /// @return True if the cipher suite is AEAD, false otherwise.
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