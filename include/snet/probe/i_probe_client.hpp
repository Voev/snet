// snet/proxy/i_probe_connection.hpp
#pragma once

#include <functional>
#include <string>

#include <snet/layers/l3/ip_address.hpp>
#include <snet/probe/probe_result.hpp>

namespace snet::probe
{

class IProbeClient
{
public:
    using Callback = std::function<void(ProbeResult)>;
    virtual ~IProbeClient() = default;
    virtual void asyncProbe(std::string sni, const layers::IPAddress& serverIP, uint16_t serverPort, Callback cb) = 0;
};

} // namespace snet::probe