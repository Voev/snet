/// @file
/// @brief Declaration of the TLS settings classes.

#pragma once
#include <snet/tls/version.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/connection.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::tls
{

/// @brief Class for managing TLS settings.
class Settings : public utils::NonCopyable
{
public:
    /// @brief Constructor with side.
    /// @param side The side (client or server).
    explicit Settings(Side side);

    /// @brief Destructor.
    virtual ~Settings() noexcept;

    /// @brief Gets the side (client or server).
    /// @return The side.
    virtual Side side() const = 0;

    /// @brief Loads a private key from a file.
    /// @param filename The filename of the private key.
    void loadPrivateKey(std::string_view filename);

    /// @brief Uses a private key.
    /// @param privateKey The private key.
    void usePrivateKey(EVP_PKEY* privateKey);

    /// @brief Loads a certificate from a file.
    /// @param filename The filename of the certificate.
    void loadCertificate(std::string_view filename);

    /// @brief Uses a certificate.
    /// @param certificate The certificate.
    void useCertificate(X509* certificate);

    /// @brief Sets the maximum protocol version.
    /// @param version The maximum protocol version.
    void setMaxVersion(const ProtocolVersion& version);

    /// @brief Sets the minimum protocol version.
    /// @param version The minimum protocol version.
    void setMinVersion(const ProtocolVersion& version);

    /// @brief Sets the verify callback.
    /// @param mode The verify mode.
    /// @param callback The verify callback.
    void setVerifyCallback(VerifyMode mode, VerifyCallback callback) noexcept;

    /// @brief Sets the mode.
    /// @param mode The mode.
    void setMode(Mode mode);

    /// @brief Sets the session cache mode.
    /// @param mode The session cache mode.
    void setSessionCacheMode(unsigned long mode);

    /// @brief Sets the options.
    /// @param options The options.
    void setOptions(unsigned long options);

    /// @brief Sets the groups list.
    /// @param groupsList The groups list.
    void setGroupsList(std::string_view groupsList);

    /// @brief Sets the cipher list.
    /// @param cipherList The cipher list.
    void setCipherList(std::string_view cipherList);

    /// @brief Sets the cipher suites.
    /// @param cipherSuites The cipher suites.
    void setCipherSuites(std::string_view cipherSuites);

    /// @brief Sets the security level.
    /// @param cipherSuites The security level.
    void setSecurityLevel(SecurityLevel level) noexcept;

    Connection createConnection() const;

private:
    SslCtxPtr ctx_;
};

/// @brief Class for managing client TLS settings.
class ClientSettings final : public Settings
{
public:
    /// @brief Default constructor.
    ClientSettings()
        : Settings(Side::Client)
    {
    }

    /// @brief Destructor.
    ~ClientSettings() = default;

    /// @brief Gets the side (client or server).
    /// @return The side.
    Side side() const override
    {
        return Side::Client;
    }
};

/// @brief Class for managing server TLS settings.
class ServerSettings final : public Settings
{
public:
    /// @brief Default constructor.
    ServerSettings()
        : Settings(Side::Server)
    {
    }

    /// @brief Destructor.
    ~ServerSettings() = default;

    /// @brief Gets the side (client or server).
    /// @return The side.
    Side side() const override
    {
        return Side::Server;
    }
};

} // namespace snet::tls