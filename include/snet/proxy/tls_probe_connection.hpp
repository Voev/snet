#pragma once

#include <algorithm>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <snet/proxy/i_probe_connection.hpp>
#include <snet/proxy/tls_probe_connection.hpp>   // TlsProbeResult
#include <snet/probe/probe_connector.hpp>
#include <snet/probe/probe_handle.hpp>
#include <snet/probe/probe_result.hpp>

namespace snet::proxy
{

template <typename SessionManagerType>
class ProbeConnectorAdapter : public IProbeConnection
{
public:
    ProbeConnectorAdapter(snet::probe::ProbeConnector<SessionManagerType>& connector,
                          layers::IPAddress sourceIP)
        : connector_(connector)
        , sourceIP_(sourceIP)
    {
    }

    ~ProbeConnectorAdapter() override
    {
        std::vector<std::shared_ptr<snet::probe::ProbeHandle>> pending;
        {
            std::lock_guard lk(mtx_);
            pending.swap(handles_);
        }
        for (auto& h : pending)
            if (h) h->abort("adapter destroyed");
    }

    void asyncProbe(std::string sni, layers::IPAddress serverIP,
                    uint16_t serverPort, Callback cb) override
    {
        auto handle = connector_.start(
            std::move(sni),
            serverIP,
            serverPort,
            sourceIP_,
            [cb = std::move(cb)](snet::probe::ProbeResult r) mutable
            {
                probe::ProbeResult tls;
                tls.status  = mapStatus(r.status);
                tls.error   = std::move(r.error);
                tls.version = r.version;
                tls.chain   = std::move(r.chain);
                cb(std::move(tls));
            });

        std::lock_guard lk(mtx_);
        if (handle)
            handles_.push_back(std::move(handle));
    }

private:
    static probe::ProbeResult::Status mapStatus(snet::probe::ProbeResult::Status s)
    {
        using PS = snet::probe::ProbeResult::Status;
        switch (s)
        {
        case PS::Ok:               return probe::ProbeResult::Status::Ok;
        case PS::ConnectFailed:    return probe::ProbeResult::Status::ConnectFailed;
        case PS::ConnectTimeout:   return probe::ProbeResult::Status::ConnectTimeout;
        case PS::HandshakeTimeout: return probe::ProbeResult::Status::HandshakeTimeout;
        case PS::TlsError:         return probe::ProbeResult::Status::TlsError;
        case PS::NoCertificate:    return probe::ProbeResult::Status::NoCertificate;
        case PS::Cancelled:        return probe::ProbeResult::Status::Cancelled;
        }
        return probe::ProbeResult::Status::ConnectFailed;
    }

    snet::probe::ProbeConnector<SessionManagerType>& connector_;
    layers::IPAddress                                 sourceIP_;
    std::mutex                                        mtx_;
    std::vector<std::shared_ptr<snet::probe::ProbeHandle>> handles_;
};

} // namespace snet::proxy