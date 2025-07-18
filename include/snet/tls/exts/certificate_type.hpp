#pragma once
#include <string>
#include <vector>
#include <snet/tls/types.hpp>
#include <snet/tls/exts/extension.hpp>

namespace snet::tls
{

/// @brief Certificate types as defined in RFC 8446 4.4.2.
enum class CertificateType : uint8_t
{
    X509 = 0,        ///< X.509 certificate.
    RawPublicKey = 2 ///< Raw public key.
};

/// @brief Converts a CertificateType to a string representation.
///
/// @param[in] type The CertificateType to convert.
///
/// @return The string representation of the CertificateType.
std::string CertificateTypeToString(CertificateType type);

/// @brief Converts a string representation to a CertificateType.
///
/// @param[in] typeStr The string representation to convert.
///
/// @return The corresponding CertificateType.
CertificateType CertificateTypeFromString(const std::string& typeStr);

/// @brief Base class for 'ClientCertificateType' and 'ServerCertificateType' extensions (RFC 7250).
class CertificateTypeBase : public Extension
{
public:
    /// @brief Constructor called by the client to advertise support for a number of certificate
    /// types.
    ///
    /// @param[in] supportedCertTypes The supported certificate types.
    CertificateTypeBase(std::vector<CertificateType> supportedCertTypes);

protected:
    /// @brief Constructor called by the server to select a certificate type to be used in the
    /// handshake.
    ///
    /// @param[in] certificateTypeFromClient The certificate type from the client.
    /// @param[in] serverPreference The server's preferred certificate types.
    CertificateTypeBase(const CertificateTypeBase& certificateTypeFromClient,
                        const std::vector<CertificateType>& serverPreference);

public:
    /// @brief Checks if the extension should be encoded.
    ///
    /// @retval true Should be encoded.
    /// @retval false Otherwise.
    bool empty() const override
    {
        // RFC 7250 4.1
        //    If the client has no remaining certificate types to send in the
        //    client hello, other than the default X.509 type, it MUST omit the
        //    entire client[/server]_CertificateType extension [...].
        return from_ == Side::Client && certTypes_.size() == 1 && certTypes_.front() == CertificateType::X509;
    }

    /// @brief Serialize extension to bytes.
    ///
    /// @param[in] side Side (Client or Server).
    /// @param[in] output Buffer for encoding.
    ///
    /// @return Serialized bytes count.
    size_t serialize(Side side, nonstd::span<uint8_t> output) const override;

    /// @brief Constructor with input byte buffer.
    ///
    /// @param[in] side Side (client or server).
    /// @param[in] input Input byte buffer.
    ///
    CertificateTypeBase(Side side, nonstd::span<const uint8_t> input);

    /// @brief Validates the selected certificate type from the server.
    ///
    /// @param[in] fromServer The certificate type from the server.
    void validateSelection(const CertificateTypeBase& fromServer) const;

    /// @brief Gets the selected certificate type.
    ///
    /// @return The selected certificate type.
    CertificateType selectedCertificateType() const;

private:
    std::vector<CertificateType> certTypes_;
    Side from_;
};

/// @brief Client Certificate Type extension (RFC 7250).
class ClientCertificateType final : public CertificateTypeBase
{
public:
    using CertificateTypeBase::CertificateTypeBase;

    /// @brief Creates the Server Hello extension from the received client preferences.
    ///
    /// @param[in] cct The client certificate type.
    ClientCertificateType(const ClientCertificateType& cct);

    /// @brief Gets the static type of the extension.
    ///
    /// @return The extension code for client certificate type.
    static ExtensionCode staticType();

    /// @brief Gets the type of the extension.
    ///
    /// @return The extension code for client certificate type.
    ExtensionCode type() const override;
};

/// @brief Server Certificate Type extension (RFC 7250).
class ServerCertificateType final : public CertificateTypeBase
{
public:
    using CertificateTypeBase::CertificateTypeBase;

    /// @brief Creates the Server Hello extension from the received client preferences.
    ///
    /// @param[in] sct The server certificate type.
    ServerCertificateType(const ServerCertificateType& sct);

    /// @brief Gets the static type of the extension.
    ///
    /// @return The extension code for server certificate type.
    static ExtensionCode staticType();

    /// @brief Gets the type of the extension.
    ///
    /// @return The extension code for server certificate type.
    ExtensionCode type() const override;
};

} // namespace snet::tls