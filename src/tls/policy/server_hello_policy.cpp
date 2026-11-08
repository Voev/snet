#include <snet/tls/policy/server_hello_policy.hpp>

#include <snet/tls/session.hpp>

namespace snet::tls
{

ServerHelloPolicy ServerHelloPolicy::make(const ServerHello& src, const Session& processedOn) noexcept
{
    ServerHelloPolicy p;
    const auto& exts = processedOn.getServerExtensions();

    // Version: TLS 1.3 carries the real version in supported_versions;
    // legacy_version is 0x0303. For <= TLS 1.2 use src.version directly.
    p.version = src.version;
    if (exts.has(ExtensionCode::SupportedVersions))
    {
        if (auto* sv = exts.get<SupportedVersions>())
        {
            auto versions = sv->versions();
            if (!versions.empty())
                p.version = versions.front();
        }
    }

    // Cipher suite: verbatim from the wire.
    p.suite = src.cipherSuite;

    // Key share group: the group the real server chose. This is the group
    // in which constructServerHello must generate our own ephemeral key.
    // For TLS 1.2 / PSK-only ServerHello there is no key_share: group stays NONE.
    if (exts.has(ExtensionCode::KeyShare))
    {
        if (auto* ks = exts.get<KeyShare>())
        {
            std::vector<crypto::GroupParams> groups;
            ks->offeredGroups(groups);
            if (!groups.empty())
                p.group = groups.front();
        }
    }

    // Session ID: direct view into SH wire bytes.
    p.sessionId = src.sessionID;

    // Signature algorithms: on the client side of MITM these live in the
    // client's ClientHello extensions, not in ServerHello. The ServerHello
    // extension list does not carry signature_algorithms. So we leave the
    // view empty here; CertificateVerify construction (server side of MITM)
    // will consult clientExtensions_ directly when the time comes.
    //
    // If later you decide to carry them in the policy (e.g. to avoid a
    // second lookup), populate from processedOn.getClientExtensions() here
    // — but that would require processedOn to be the client-side Session.
    // p.signatureAlgorithms stays empty.

    // Flags: mirror what the real server negotiated, so constructServerHello
    // can emit the same extensions towards the client.
    p.useEncryptThenMac = exts.has(ExtensionCode::EncryptThenMac);
    p.useExtendedMasterSecret = exts.has(ExtensionCode::ExtendedMasterSecret);
    p.useSessionTicket = exts.has(ExtensionCode::SessionTicket);
    p.useRenegotiationInfo = exts.has(ExtensionCode::SafeRenegotiation);

    return p;
}

} // namespace snet::tls