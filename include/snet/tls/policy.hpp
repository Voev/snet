#pragma once
#include <snet/utils/algorithm.hpp>
#include <snet/crypto/group_params.hpp>

namespace snet::tls
{

crypto::GroupParams ChooseKeyExchangeGroup(nonstd::span<const crypto::GroupParams> supportedByPeer,
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