#pragma once

#include <cstdint>
#include <string_view>

namespace snet::probe
{

struct ProbeKey;

/// @brief Owner interface for ProbeHandle.
///
/// ProbeHandle calls finalizeProbe/abortProbe on completion/timeout.
/// Implemented by ProbeConnector<SessionManagerType>.
class IProbeOwner
{
public:
    virtual ~IProbeOwner() = default;

    virtual void finalizeProbe(void* session, uint32_t key, const ProbeKey& flowKey) = 0;
    virtual void abortProbe(void* session, uint32_t key, const ProbeKey& flowKey,
                            std::string_view reason) = 0;
};

} // namespace snet::probe