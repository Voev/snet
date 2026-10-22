#pragma once

#include <string_view>
#include <vector>

#include <snet/crypto/cert.hpp>
#include <snet/layers/packet_status.hpp>

namespace snet::proxy
{

/// Action to take for a connection pair after inspection.
enum class InspectionDecision
{
    Bypass, ///< Pass traffic through without interception.
    Mitm,   ///< Intercept via TLS termination (man-in-the-middle).
    Block,  ///< Drop the connection.
};

/// Lifecycle phase of a connection pair.
enum class PairPhase
{
    Waiting, ///< Client TCP established; awaiting ClientHello.
    Probing, ///< ClientHello received; probe in flight.
    Splice,  ///< Bypass decided; bytes are relayed as-is.
    Mitm,    ///< Mitm decided; TLS termination active.
    Closed,  ///< Pair is closed.
};

/// Ordered chain of X.509 certificates.
using CertificateChain = std::vector<snet::crypto::X509CertPtr>;

/// Map a pair phase to the packet verdict the driver must apply.
///
///   Waiting  — TCP established, ClientHello not yet parsed.
///              Original must reach the server: Pass/Observed.
///
///   Probing  — Probe in flight. Original still leaves: Pass/Probing.
///
///   Splice   — Bypass decided. Consumer relays bytes into txRing.
///              Original must NOT leave (double-send): Drop/Bypass.
///
///   Mitm     — TLS termination. Original not needed: Drop/Hijacked.
///
///   Closed   — Connection closed: Drop/Closed.
///
/// @param[in] phase Current pair phase.
/// @return Packet status (pass/drop with reason) for the driver.
[[nodiscard]] constexpr snet::layers::PacketStatus verdictFromPhase(PairPhase phase) noexcept
{
    using snet::layers::PacketStatus;
    using snet::layers::PacketReason;

    switch (phase)
    {
    case PairPhase::Waiting:
    {
        return PacketStatus::pass(PacketReason::Observed);
    }
    case PairPhase::Probing:
    {
        // During probe the packet must NOT be re-injected by the driver:
        // the consumer already holds the bytes in pair.bufferedClientHello
        // and will re-emit them via pushToUpstream once a decision is made.
        // Emitting via bridge would cause a double-send to the server.
        return PacketStatus::drop(PacketReason::Probing);
    }
    case PairPhase::Splice:
        return PacketStatus::drop(PacketReason::Bypass);
    case PairPhase::Mitm:
        return PacketStatus::drop(PacketReason::Hijacked);
    case PairPhase::Closed:
        return PacketStatus::drop(PacketReason::Closed);
    }
    return PacketStatus::drop(PacketReason::Error);
}

} // namespace snet::proxy