#pragma once

#include <cstdint>

namespace snet::tls
{

/// Enumeration of the TLS extension codes.
enum class ExtensionCode : uint16_t
{
    ServerNameIndication = 0,
    SupportedGroups = 10,
    ECPointFormats = 11,
    SignatureAlgorithms = 13,
    AppLayerProtocolNegotiation = 16,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    EncryptThenMac = 22,
    ExtendedMasterSecret = 23,
    RecordSizeLimit = 28,
    SessionTicket = 35,
    SupportedVersions = 43,
    PskKeyExchangeModes = 45,
    CertSignatureAlgorithms = 50,
    KeyShare = 51,
    SafeRenegotiation = 65281,
};

/// @brief Serialization error sentinel returned by `serialize` methods.
///
/// Every extension's `serialize` returns either the number of bytes written
/// (including `0` for empty bodies) or this value on failure (buffer too
/// small, body exceeds the 16-bit length field, server invariant violated).
inline constexpr std::size_t kSerializationFailed = static_cast<std::size_t>(-1);

/// Human-readable name. `constexpr noexcept`, no allocation.
constexpr const char* toString(ExtensionCode code) noexcept
{
    switch (code)
    {
    case ExtensionCode::ServerNameIndication:
        return "ServerNameIndication";
    case ExtensionCode::SupportedGroups:
        return "SupportedGroups";
    case ExtensionCode::ECPointFormats:
        return "ECPointFormats";
    case ExtensionCode::SignatureAlgorithms:
        return "SignatureAlgorithms";
    case ExtensionCode::AppLayerProtocolNegotiation:
        return "AppLayerProtocolNegotiation";
    case ExtensionCode::ClientCertificateType:
        return "ClientCertificateType";
    case ExtensionCode::ServerCertificateType:
        return "ServerCertificateType";
    case ExtensionCode::EncryptThenMac:
        return "EncryptThenMac";
    case ExtensionCode::ExtendedMasterSecret:
        return "ExtendedMasterSecret";
    case ExtensionCode::RecordSizeLimit:
        return "RecordSizeLimit";
    case ExtensionCode::SessionTicket:
        return "SessionTicket";
    case ExtensionCode::SupportedVersions:
        return "SupportedVersions";
    case ExtensionCode::CertSignatureAlgorithms:
        return "CertSignatureAlgorithms";
    case ExtensionCode::PskKeyExchangeModes:
        return "PskKeyExchangeModes";
    case ExtensionCode::KeyShare:
        return "KeyShare";
    case ExtensionCode::SafeRenegotiation:
        return "SafeRenegotiation";
    }
    return "UnknownExtension";
}

} // namespace snet::tls