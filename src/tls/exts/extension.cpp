#include <snet/tls/exts/extension.hpp>

namespace snet::tls
{

const char* ExtensionCodeToString(const ExtensionCode code)
{
    switch (code)
    {
    case ExtensionCode::ServerNameIndication:
        return "ServerNameIndication";
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
    case ExtensionCode::SafeRenegotiation:
        return "SafeRenegotiation";
    case ExtensionCode::KeyShare:
        return "KeyShare";
    default:
        return "UnknownExtension";
    }
}

} // namespace snet::tls