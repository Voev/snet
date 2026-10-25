#pragma once

#include <snet/tcp/tcp_stream.hpp>
#include <snet/probe/probe_context.hpp>
#include <snet/probe/probe_acceptor.hpp>
#include <snet/proxy/transparent_proxy_acceptor.hpp>

namespace snet::probe
{

template <typename SessionManagerType>
class UnifiedAcceptor : public snet::tcp::IConnectionAcceptor<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;
    using TcpConnection = snet::tcp::TcpConnection;

    UnifiedAcceptor(SessionManagerType& mgr, snet::proxy::TransparentProxyAcceptor<SessionManagerType>& clientAcceptor,
                    ProbeAcceptor<SessionManagerType>& probeAcceptor)
        : mgr_(mgr)
        , clientAcceptor_(clientAcceptor)
        , probeAcceptor_(probeAcceptor)
    {
    }

    void onAccept(Session* session, TcpConnection& conn) override
    {
        if (isProbe(session))
            probeAcceptor_.onAccept(session, conn);
        else
            clientAcceptor_.onAccept(session, conn);
    }

    void onReject(Session* session, TcpConnection& conn) override
    {
        if (isProbe(session))
            probeAcceptor_.onReject(session, conn);
        else
            clientAcceptor_.onReject(session, conn);
    }

    bool isProbe(Session* session) const
    {
        auto* probe = mgr_.template getContext<snet::probe::ProbeContext>(session);
        return probe && probe->cb != nullptr;
    }

private:
    SessionManagerType& mgr_;
    snet::proxy::TransparentProxyAcceptor<SessionManagerType>& clientAcceptor_;
    ProbeAcceptor<SessionManagerType>& probeAcceptor_;
};

} // namespace snet::probe