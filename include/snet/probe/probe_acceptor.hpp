#pragma once

#include <snet/tcp/tcp_stream.hpp>
#include <snet/tcp/tcp_transmit_handler.hpp>
#include <snet/tls/session.hpp>
#include <snet/tls/record_pool.hpp>

#include <snet/probe/probe_context.hpp>
#include <snet/probe/probe_result.hpp>

#include <casket/log/log.hpp>

namespace snet::probe
{

std::vector<uint8_t> buildClientHelloRecord(std::string_view sni, tls::ProtocolVersion preferred, tls::RecordPool& pool,
                                            tls::Session& session);

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

        std::vector<uint8_t> bytes;
        try
        {
            bytes = buildClientHelloRecord(probe->sni, cfg_.preferredVersion, *probe->tlsPool, *probe->tls);
        }
        catch (const std::exception& e)
        {
            CSK_LOG_ERROR("ProbeAcceptor: buildClientHelloRecord threw: %s", e.what());
            if (!probe->done.exchange(true) && probe->cb)
            {
                ProbeResult r;
                r.status = ProbeResult::Status::TlsError;
                r.error = std::string("buildClientHelloRecord: ") + e.what();
                probe->cb(std::move(r));
            }
            if (auto h = probe->handle.lock())
                h->complete();
            return;
        }

        const size_t written = tx_.sendData(session, bytes.data(), bytes.size());
        if (written == 0)
            CSK_LOG_WARNING("ProbeAcceptor: sendData accepted 0 bytes (sni=%s)", probe->sni.c_str());

        CSK_LOG_DEBUG("ProbeAcceptor: ClientHello queued (%zu bytes, sni=%s)", written, probe->sni.c_str());
    }

    void onReject(Session* /*session*/, TcpConnection& /*conn*/) override
    {
    }

private:
    SessionManagerType& mgr_;
    TxHandler& tx_;
    ProbeAcceptorConfig cfg_;
};

} // namespace snet::probe