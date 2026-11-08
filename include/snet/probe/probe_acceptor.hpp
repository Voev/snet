#pragma once

#include <snet/tcp/tcp_stream.hpp>
#include <snet/tcp/tcp_transmit_handler.hpp>
#include <snet/tls/session.hpp>
#include <snet/tls/record_pool.hpp>

#include <snet/probe/probe_context.hpp>
#include <snet/probe/probe_result.hpp>
#include <snet/probe/tcp_byte_writer.hpp>

#include <casket/log/log.hpp>

namespace snet::probe
{

/// @brief Probe-side acceptor config.
struct ProbeAcceptorConfig
{
    tls::ProtocolVersion preferredVersion{tls::ProtocolVersion::TLSv1_3};
    size_t recordPoolSize{4};
};

/// @brief Probe-side acceptor: on Established, send ClientHello via txRing.
template <typename SessionManagerType>
class ProbeAcceptor : public snet::tcp::IConnectionAcceptor<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;
    using TcpConnection = snet::tcp::TcpConnection;
    using TxHandler = snet::tcp::TcpTransmitHandler<SessionManagerType>;

    ProbeAcceptor(SessionManagerType& mgr, TxHandler& tx, ProbeAcceptorConfig cfg = {})
        : mgr_(mgr)
        , tx_(tx)
        , cfg_(cfg)
    {
    }

    void onAccept(Session* session, TcpConnection& /*conn*/) override
    {
        auto* probe = mgr_.template getContext<ProbeContext>(session);
        if (!probe || !probe->tls)
            return;

        if (probe->clientHelloSent.exchange(true))
            return;

        try
        {
            tls::ClientHelloPolicy policy{};
            probe->tls->constructClientHello(policy);

            probe::TcpByteWriter<SessionManagerType> writer(tx_, session);
            const std::size_t flushed = probe->tls->flush(writer);
            if (flushed == 0)
            {
                CSK_LOG_WARNING("ProbeAcceptor: flush deferred (sni=%s)", probe->sni.c_str());
            }
        }
        catch (const std::exception& e)
        {
            CSK_LOG_ERROR("ProbeAcceptor: failed to send client hello: %s", e.what());

            if (!probe->done.exchange(true) && probe->cb)
            {
                ProbeResult r;
                r.status = ProbeResult::Status::TlsError;
                probe->cb(std::move(r));
            }

            if (auto h = probe->handle.lock())
            {
                h->complete();
            }
            return;
        }
    }

    void onReject(Session* session, TcpConnection& conn) override
    {
        (void)session;
        (void)conn;
    }

private:
    SessionManagerType& mgr_;
    TxHandler& tx_;
    ProbeAcceptorConfig cfg_;
};

} // namespace snet::probe