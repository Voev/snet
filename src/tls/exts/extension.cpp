#include <snet/tls/exts/extension.hpp>

namespace snet::tls
{

const char* ExtensionCodeToString(const ExtensionCode code)
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
    case ExtensionCode::SupportedVersions:
        return "SupportedVersions";
    case ExtensionCode::CertSignatureAlgorithms:
        return "CertSignatureAlgorithms";
    case ExtensionCode::KeyShare:
        return "KeyShare";
    case ExtensionCode::SafeRenegotiation:
        return "SafeRenegotiation";
    default:
        return "UnknownExtension";
    }
}

} // namespace snet::tls