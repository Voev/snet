#pragma once
#include <cstdint>
#include <snet/cpp_port/span.hpp>
#include <snet/tls/types.hpp>

namespace snet::tls
{

/// @brief Enumeration of the TLS extension codes.
enum class ExtensionCode : uint16_t
{
    ServerNameIndication = 0,         ///< Server Name Indication (SNI) extension.
    SupportedGroups = 10,             ///< Supported Groups Extension (RFC 7919).
    ECPointFormats = 11,              ///< Supported EC Point Formats.
    AppLayerProtocolNegotiation = 16, ///< Application Layer Protocol Negotiation (ALPN) extension.
    ClientCertificateType = 19,       ///< Client Certificate Type extension.
    ServerCertificateType = 20,       ///< Server Certificate Type extension.
    EncryptThenMac = 22,              ///< Encrypt-then-MAC extension.
    ExtendedMasterSecret = 23,        ///< Extended Master Secret extension.
    RecordSizeLimit = 28,             ///< Record Size Limit extension.
    SupportedVersions = 43,           ///< Supported Versions extension.
    SafeRenegotiation = 65281,        ///< Safe Renegotiation extension.
};

const char* ExtensionCodeToString(const ExtensionCode code);

/// @brief Base class for TLS extensions.
class Extension
{
public:
    /// @brief Virtual destructor.
    virtual ~Extension() = default;

    /// @brief Gets the type of the extension.
    ///
    /// @return The extension code.
    virtual ExtensionCode type() const = 0;

    /// @brief Checks if the extension should be encoded.
    ///
    /// @return true if the extension should be encoded, false otherwise.
    virtual bool empty() const = 0;

    /// @brief Serialize extension to bytes.
    ///
    /// @param[in] side Side (Client or Server).
    /// @param[in] output Buffer for encoding.
    ///
    /// @return Serialized bytes count.
    virtual size_t serialize(Side side, cpp::span<uint8_t> output) const = 0;
};

} // namespace snet::tls