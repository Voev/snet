#include <snet/probe/probe_acceptor.hpp>

#include <array>
#include <cstdint>
#include <vector>

#include <snet/crypto/group_params.hpp>
#include <snet/crypto/signature_scheme.hpp>

#include <snet/tls/exts/key_share.hpp>
#include <snet/tls/exts/server_name_indication.hpp>
#include <snet/tls/exts/signature_algorithms.hpp>
#include <snet/tls/exts/supported_groups.hpp>
#include <snet/tls/exts/supported_versions.hpp>
#include <snet/tls/extensions.hpp>
#include <snet/tls/msgs/client_hello.hpp>
#include <snet/tls/record.hpp>
#include <snet/tls/record_pool.hpp>
#include <snet/tls/record_printer.hpp>
#include <snet/tls/session.hpp>

using namespace snet::tls;
using namespace snet::crypto;
using namespace snet::utils;

namespace snet::probe
{

/// @brief Builds the extensions block for the probe's ClientHello.
///
/// @param[in] sni Server Name Indication; may be empty.
/// @return Serialized `<2-byte total length> <ext>*` bytes, or empty on error.
std::vector<uint8_t> buildClientHelloExtensions(std::string_view sni)
{
    tls::Extensions exts;

    if (!sni.empty())
    {
        exts.add(tls::ExtensionVariant(tls::ServerNameIndicator(sni)));
    }

    // supported_groups (RFC 8446 §4.2.7)
    {
        std::vector<crypto::GroupParams> groups;
        groups.emplace_back(crypto::GroupParams::Code::X25519);
        groups.emplace_back(crypto::GroupParams::Code::SECP256R1);
        exts.add(tls::ExtensionVariant(tls::SupportedGroups(std::move(groups))));
    }

    // signature_algorithms (RFC 8446 §4.2.3)
    {
        std::vector<crypto::SignatureScheme> schemes;
        schemes.emplace_back(crypto::SignatureScheme::Code::ECDSA_SHA256);
        schemes.emplace_back(crypto::SignatureScheme::Code::RSA_PSS_RSAE_SHA256);
        schemes.emplace_back(crypto::SignatureScheme::Code::RSA_PKCS1_SHA256);
        exts.add(tls::ExtensionVariant(tls::SignatureAlgorithms(std::move(schemes))));
    }

    // supported_versions (RFC 8446 §4.2.1)
    {
        std::vector<tls::ProtocolVersion> versions = {
            tls::ProtocolVersion::TLSv1_3,
            tls::ProtocolVersion::TLSv1_2,
        };
        exts.add(tls::ExtensionVariant(tls::SupportedVersions(std::move(versions))));
    }

    // key_share (RFC 8446 §4.2.8)
    //
    // The actual key_exchange bytes are filled later by
    // Session::constructClientHello (it generates the ephemeral X25519 key
    // and calls KeyShare::setPublicKey).
    {
        std::vector<crypto::GroupParams> groups;
        groups.emplace_back(crypto::GroupParams::Code::X25519);
        exts.add(tls::ExtensionVariant(tls::KeyShare(std::move(groups))));
    }

    std::vector<uint8_t> out(2 * 1024);
    const std::size_t n = exts.serialize(tls::Side::Client, {out.data(), out.size()});
    if (n == 0)
    {
        return {};
    }
    out.resize(n);
    return out;
}

/// @brief Cipher suites offered by the probe (TLS 1.3 + TLS 1.2 ECDHE/DHE).
constexpr std::array<std::uint8_t, 14> kProbeSuites = {
    0x13,
    0x01, // TLS_AES_128_GCM_SHA256
    0x13,
    0x02, // TLS_AES_256_GCM_SHA384
    0x13,
    0x03, // TLS_CHACHA20_POLY1305_SHA256
    0xC0,
    0x2F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC0,
    0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0x00,
    0x9E, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    0x00,
    0x9F, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
};

/// @brief Compression methods offered by the probe (only `null`).
constexpr std::array<std::uint8_t, 1> kProbeCompMethods = {0x00};

std::vector<uint8_t> buildClientHelloRecord(std::string_view sni, tls::ProtocolVersion preferred, tls::RecordPool& pool,
                                            tls::Session& session)
{
    // 1. Extensions block (serialized once; kept alive for the whole function
    //    because ClientHello.extensions is a non-owning view).
    std::vector<uint8_t> extBytes = buildClientHelloExtensions(sni);
    if (extBytes.empty())
    {
        return {};
    }

    // 2. ClientHello with the fixed fields. Session::constructClientHello
    //    will fill random, sessionID, and key_share's key_exchange.
    tls::ClientHello ch{};
    ch.version = preferred;
    ch.suites = {kProbeSuites.data(), kProbeSuites.size()};
    ch.compMethods = {kProbeCompMethods.data(), kProbeCompMethods.size()};
    ch.extensions = {extBytes.data(), extBytes.size()};

    session.setVersion(preferred);
    session.constructClientHello(ch);

    // 3. Serialize into a Record from the pool.
    auto* rec = pool.acquire();
    if (!rec)
    {
        return {};
    }

    const std::size_t serialized = rec->serializeHandshake(HandshakeMessage(std::move(ch)), 0, session);
    if (serialized == kSerializationFailed)
    {
        pool.release(rec);
        return {};
    }

    tls::PrintRecord(0, &session, rec);

    session.addOutgoingRecord(0, rec);

    // 4. Flush records into the output buffer. 16 KiB is the maximum TLS
    //    record size, which is more than enough for a ClientHello.
    std::vector<uint8_t> out(16 * 1024);
    const std::size_t n = session.writeRecords({out.data(), out.size()});
    if (n == 0)
    {
        return {};
    }
    out.resize(n);
    return out;
}

} // namespace snet::probe