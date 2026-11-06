/// @file
/// @brief Policy extracted from a ClientHello, used to build our own
///        ClientHello (for upstream) and ServerHello (for the client).

#pragma once

#include <casket/nonstd/string_view.hpp>
#include <casket/nonstd/span.hpp>

#include <snet/tls/version.hpp>

#include <snet/crypto/pointers.hpp>
#include <snet/crypto/group_params.hpp>
#include <snet/crypto/signature_scheme.hpp>

namespace snet::tls
{

class Session;
struct ClientHello;

struct ClientHelloPolicy final
{
    nonstd::string_view sni;
    nonstd::span<const ProtocolVersion> versions;
    nonstd::span<const std::uint16_t> suites;
    nonstd::span<const crypto::GroupParams> groups;
    nonstd::span<const std::uint8_t> sessionId;
    nonstd::span<const crypto::SignatureScheme> signatureAlgorithms;
    nonstd::span<const nonstd::string_view> alpn;

    ProtocolVersion legacyVersion = ProtocolVersion::TLSv1_2;
    bool useEncryptThenMac = true;
    bool useExtendedMasterSecret = true;
    bool useSessionTicket = false;
    bool useRenegotiationInfo = false;

    static ClientHelloPolicy make(const ClientHello& src, const Session& processedOn,
                                  nonstd::span<ProtocolVersion> versionsBuf) noexcept;
};

} // namespace snet::tls