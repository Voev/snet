#pragma once

#include <algorithm>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <snet/probe/i_probe_client.hpp>
#include <snet/probe/probe_connector.hpp>
#include <snet/probe/probe_handle.hpp>
#include <snet/probe/probe_result.hpp>

namespace snet::probe
{

template <typename SessionManagerType>
class ProbeClient : public IProbeClient
{
public:
    ProbeClient(ProbeConnector<SessionManagerType>& connector, layers::IPAddress sourceIP)
        : connector_(connector)
        , sourceIP_(sourceIP)
    {
    }

    ~ProbeClient() override
    {
        for (auto& h : handles_)
        {
            if (h)
            {
                h->abort();
            }
        }
    }

    void asyncProbe(std::string sni, const layers::IPAddress& serverIP, uint16_t serverPort, Callback cb) override
    {
        auto handle = connector_.start(std::move(sni), serverIP, serverPort, sourceIP_, std::move(cb));
        if (handle)
        {
            handles_.push_back(std::move(handle));
        }
    }

private:
    ProbeConnector<SessionManagerType>& connector_;
    layers::IPAddress sourceIP_;
    std::vector<std::shared_ptr<ProbeHandle>> handles_;
};

} // namespace snet::probe