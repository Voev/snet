#pragma once
#include <cstdint>

namespace snet::probe
{

class IProbeOwner
{
public:
    virtual ~IProbeOwner() = default;

    virtual void finalizeProbe(void* session, uint32_t key) = 0;
    virtual void abortProbe(void* session, uint32_t key) = 0;
};

} // namespace snet::probe