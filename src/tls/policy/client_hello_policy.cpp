#include <snet/tls/policy/client_hello_policy.hpp>

#include <snet/tls/session.hpp>

namespace snet::tls
{

ClientHelloPolicy ClientHelloPolicy::make(const ClientHello& src, const Session& processedOn,
                                          nonstd::span<ProtocolVersion> versionsBuf) noexcept
{
    ClientHelloPolicy p;
    const auto& exts = processedOn.getClientExtensions();

    // SNI: direct view into the extension.
    if (exts.has(ExtensionCode::ServerNameIndication))
        p.sni = exts.get<ServerNameIndicator>()->getHostname();

    // Versions: from supported_versions or fallback to legacy_version.
    std::size_t vCount = 0;
    if (exts.has(ExtensionCode::SupportedVersions))
    {
        for (auto v : exts.get<SupportedVersions>()->versions())
            if (vCount < versionsBuf.size())
                versionsBuf[vCount++] = v;
    }
    else
    {
        versionsBuf[0] = src.version;
        vCount = 1;
    }
    p.versions = {versionsBuf.data(), vCount};

    // Cipher suites: direct view into CH wire bytes (big-endian pairs).
    p.suites = src.suites;

    // Groups: direct view into extension.
    if (exts.has(ExtensionCode::SupportedGroups))
        p.groups = exts.get<SupportedGroups>()->groups();

    // Session ID: direct view into CH.
    p.sessionId = src.sessionID;

    // Signature algorithms: direct view into extension.
    if (exts.has(ExtensionCode::SignatureAlgorithms))
        p.signatureAlgorithms = exts.get<SignatureAlgorithms>()->supportedSchemes();

    // Legacy version derived from the highest offered version.
    p.legacyVersion =
        (vCount == 0 || versionsBuf[0] >= ProtocolVersion::TLSv1_3) ? ProtocolVersion::TLSv1_2 : versionsBuf[0];

    return p;
}

} // namespace snet::tls