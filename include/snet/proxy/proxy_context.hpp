#pragma once

#include <cstdint>

#include "proxy_pair.hpp"

namespace snet::proxy
{

struct ProxyContext
{
    static constexpr size_t MAX_INSTANCES = 1;

    ProxyPairPtr pair;

    bool isDownstream{false};
    bool isUpstream{false};

    uint32_t downstreamKey{0};
    uint32_t upstreamKey{0};

    snet::layers::IPAddress clientIP{};
    uint16_t                clientPort{0};
    snet::layers::IPAddress serverIP{};
    uint16_t                serverPort{0};


    [[nodiscard]] bool isObserving() const noexcept
    {
        if (!pair)
            return true;
        return pair->phase == PairPhase::Waiting
            || pair->phase == PairPhase::Probing;
    }

    [[nodiscard]] bool isAttached() const noexcept
    {
        if (!pair)
            return false;
        return pair->phase == PairPhase::Splice
            || pair->phase == PairPhase::Mitm;
    }

    [[nodiscard]] bool isSpliced() const noexcept
    {
        return pair && pair->phase == PairPhase::Splice;
    }

    [[nodiscard]] bool isMitm() const noexcept
    {
        return pair && pair->phase == PairPhase::Mitm;
    }

    [[nodiscard]] bool isClosed() const noexcept
    {
        return pair && pair->phase == PairPhase::Closed;
    }
};

} // namespace snet::proxy