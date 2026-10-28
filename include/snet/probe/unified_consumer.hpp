#pragma once

#include <snet/tcp/tcp_stream.hpp>
#include <snet/probe/probe_context.hpp>
#include <snet/probe/probe_consumer.hpp>
#include <snet/proxy/proxy_consumer.hpp>

namespace snet::probe
{

template <typename SessionManagerType>
class UnifiedConsumer : public snet::tcp::IStreamConsumer<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;

    UnifiedConsumer(SessionManagerType& mgr, snet::proxy::ProxyConsumer<SessionManagerType>& clientConsumer,
                    ProbeStreamConsumer<SessionManagerType>& probeConsumer)
        : mgr_(mgr)
        , clientConsumer_(clientConsumer)
        , probeConsumer_(probeConsumer)
    {
    }

    void onStreamData(Session* s, int8_t side, snet::tcp::IStreamReader& r) override
    {
        if (isProbe(s))
            probeConsumer_.onStreamData(s, side, r);
        else
            clientConsumer_.onStreamData(s, side, r);
    }

    void onStreamClose(Session* s, int8_t side, int reason) override
    {
        if (isProbe(s))
            probeConsumer_.onStreamClose(s, side, reason);
        else
            clientConsumer_.onStreamClose(s, side, reason);
    }

    void onStreamGap(Session* s, int8_t side, uint32_t missing) override
    {
        if (isProbe(s))
            probeConsumer_.onStreamGap(s, side, missing);
        else
            clientConsumer_.onStreamGap(s, side, missing);
    }

    bool isProbe(Session* session) const
    {
        auto* probe = mgr_.template getContext<snet::probe::ProbeContext>(session);
        return probe && probe->cb != nullptr;
    }

private:
    SessionManagerType& mgr_;
    snet::proxy::ProxyConsumer<SessionManagerType>& clientConsumer_;
    ProbeStreamConsumer<SessionManagerType>& probeConsumer_;
};

} // namespace snet::probe