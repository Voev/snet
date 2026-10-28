#pragma once

#include <cstdint>
#include <string_view>

namespace snet::probe
{

struct ProbeKey;

class IProbeOwner
{
public:
    virtual ~IProbeOwner() = default;

    virtual void finalizeProbe(void* session, uint32_t key, const ProbeKey& flowKey) = 0;
    virtual void abortProbe(void* session, uint32_t key, const ProbeKey& flowKey, std::string_view reason) = 0;
};

} // namespace snet::probe