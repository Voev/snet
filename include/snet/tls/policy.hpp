#pragma once

#include <snet/utils/algorithm.hpp>
#include <snet/crypto/group_params.hpp>
#include <snet/tls/cipher_suite.hpp>
#include <snet/tls/version.hpp>

#include <casket/nonstd/span.hpp>

namespace snet::tls
{

class Policy
{
public:
    virtual nonstd::string_view serverNameIndication() const noexcept = 0;
    virtual nonstd::span<const ProtocolVersion> supportedVersion() const noexcept = 0;
    virtual nonstd::span<const CipherSuite*> offeredCipherSuites() noexcept = 0;
    virtual nonstd::span<const crypto::GroupParams> offeredGroupParams() const noexcept = 0;

    virtual nonstd::span<std::uint8_t> clientSessionId() const noexcept = 0;
    virtual nonstd::span<nonstd::string_view> alpnProtocols() const noexcept = 0;
    virtual nonstd::span<std::uint16_t> signatureAlgorithms() noexcept = 0;

    virtual bool useEncryptThenMac() const noexcept = 0;
    virtual bool useExtendedMasterSecret() const noexcept = 0;
    virtual bool useSessionTicket() const noexcept = 0;
    virtual bool useRenegotiationInfo() const noexcept = 0;
};

/// @brief Filter `candidates` to groups present in `ourGroups`,
///        preserving candidate order.
/// @param[in]  candidates Groups to filter (policy preference order).
/// @param[in]  ourGroups  Groups our crypto backend supports.
/// @param[out] out        Output buffer.
/// @return Number of groups written; 0 if no overlap.
inline std::size_t FilterGroups(nonstd::span<const crypto::GroupParams> candidates,
                         nonstd::span<const crypto::GroupParams> ourGroups,
                         nonstd::span<crypto::GroupParams> out) noexcept
{
    std::size_t n = 0;
    for (auto g : candidates)
    {
        if (n == out.size())
            break;
        if (ValueExists(ourGroups, g))
            out[n++] = g;
    }
    return n;
}

inline crypto::GroupParams ChooseKeyExchangeGroup(nonstd::span<const crypto::GroupParams> supportedByPeer,
                                           nonstd::span<const crypto::GroupParams> offeredByPeer)
{
    if (supportedByPeer.empty())
    {
        return crypto::GroupParams::NONE;
    }

    const auto ourGroups = crypto::GroupParams::getSupported();

    // Prefer groups that were offered by the peer for the sake of saving
    // an additional round trip. For TLS 1.2, this won't be used.
    for (const auto& g : offeredByPeer)
    {
        if (ValueExists(ourGroups, g))
        {
            return g;
        }
    }

    // If no pre-offered groups fit our supported set, we prioritize our
    // own preference.
    for (auto g : ourGroups)
    {
        if (ValueExists(supportedByPeer, g))
        {
            return g;
        }
    }

    return crypto::GroupParams::NONE;
}

} // namespace snet::tls