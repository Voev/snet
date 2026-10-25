// snet/proxy/i_probe_connection.hpp
#pragma once

#include <functional>
#include <string>

#include <snet/layers/l3/ip_address.hpp>
#include <snet/probe.hpp>

namespace snet::proxy
{

class IProbeConnection
{
public:
    using Callback = std::function<void(probe::ProbeResult)>;
    virtual ~IProbeConnection() = default;
    virtual void asyncProbe(std::string sni, layers::IPAddress serverIP, uint16_t serverPort, Callback cb) = 0;
};

} // namespace snet::proxy