/// @file
/// @brief Policy extracted from a ClientHello, used to build our own
///        ClientHello (for upstream) and ServerHello (for the client).

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <snet/crypto/pointers.hpp>
#include <snet/crypto/group_params.hpp>
#include <snet/tls/version.hpp>

namespace snet::tls
{

/// @brief Policy derived from a ClientHello.
///
/// Fields are grouped by purpose, not by wire order.
struct ClientHelloPolicy
{
    /// Cipher suites we are willing to negotiate, in our preference order.
    /// Not intersected with the client here — Session::buildServerHello()
    /// picks the first suite from this list that the client also offered.
    std::vector<std::uint16_t> cipherSuites;

    /// Client's SNI (empty if none was sent).
    std::string sni;

    /// Client's legacy_session_id.
    /// - Echoed in TLS 1.3 ServerHello (middlebox compatibility).
    /// - Used as the session id for our own TLS 1.2 ClientHello.
    std::vector<std::uint8_t> clientSessionId;

    /// Client's supported_groups / elliptic_curves.
    /// - Used to pick chosenGroup if not set explicitly.
    /// - Used for TLS 1.2 ECDHE group selection.
    std::vector<crypto::GroupParams> clientSupportedGroups;

    /// Client's signature_algorithms, in client preference order.
    std::vector<std::uint16_t> clientSignatureAlgorithms;

    /// Client's legacy_version from the CH header.
    /// Kept for TLS 1.0 fallback when supported_versions is absent.
    ProtocolVersion clientLegacyVersion = ProtocolVersion::TLSv1_0;

    bool useEncryptThenMac = true;

    bool useExtendedMasterSecret = true;
};

} // namespace snet::tls