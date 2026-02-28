#pragma once
#include <snet/utils/algorithm.hpp>
#include <snet/crypto/group_params.hpp>

namespace snet::tls
{

crypto::GroupParams choose_key_exchange_group(nonstd::span<const crypto::GroupParams> supported_by_peer,
                                              nonstd::span<const crypto::GroupParams> offered_by_peer)
{
    if (supported_by_peer.empty())
    {
        return crypto::GroupParams::NONE;
    }

    const auto our_groups = crypto::GroupParams::getSupported();

    // Prefer groups that were offered by the peer for the sake of saving
    // an additional round trip. For TLS 1.2, this won't be used.
    for (const auto& g : offered_by_peer)
    {
        if (ValueExists(our_groups, g))
        {
            return g;
        }
    }

    // If no pre-offered groups fit our supported set, we prioritize our
    // own preference.
    for (auto g : our_groups)
    {
        if (ValueExists(supported_by_peer, g))
        {
            return g;
        }
    }

    return crypto::GroupParams::NONE;
}

} // namespace snet::tls