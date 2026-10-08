#pragma once

#include <random>

#include <snet/layers/checksums.hpp>
#include <snet/layers/l3/ip_proto.hpp>
#include <snet/session/session_manager.hpp>
#include <snet/tcp/tcp_state_machine.hpp>
#include <snet/tcp/tcp_transmit_handler.hpp>

#include <snet/proxy/proxy_context.hpp>

#include <casket/log/log.hpp>

namespace snet::proxy
{

/// Акцептор split-proxy.
///
/// Вызывается TcpReceiveHandler'ом, когда TCP с клиентом установлен.
/// НЕ открывает upstream сразу — только фиксирует downstream и
/// готовит pair. Открытие upstream инициируется позже, из consumer'а,
/// после того как решение (bypass/mitm) принято.
template <typename SessionManagerType>
class TransparentProxyAcceptor final : public snet::tcp::IConnectionAcceptor<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;
    using TcpConnection = snet::tcp::TcpConnection;
    using TransmitHandler = snet::tcp::TcpTransmitHandler<SessionManagerType>;

    TransparentProxyAcceptor(SessionManagerType* mgr, TransmitHandler* tx)
        : mgr_(mgr)
        , tx_(tx)
        , rng_(std::random_device{}())
    {
    }

    void onAccept(Session* downstream, TcpConnection& downConn) override
    {
        auto* ctx = mgr_->template getContext<ProxyContext>(downstream);
        if (!ctx)
        {
            CSK_LOG_ERROR("Acceptor: ProxyContext missing");
            return;
        }

        if (ctx->pair)
        {
            CSK_LOG_WARNING("Acceptor: pair created");
            return;
        }

        const bool isDownstream = (downConn.localPort == 8443);

        if (!isDownstream)
        {
            CSK_LOG_DEBUG("Acceptor: upstream onAccept — waiting for pair "
                          "(localPort=%u, remotePort=%u)",
                          downConn.localPort,
                          downConn.remotePort);
            return;
        }

        ctx->isDownstream = true;
        ctx->pair = std::make_shared<ProxyPair>();
        auto& pair = *ctx->pair;

        pair.clientIP = downConn.remoteIP;
        pair.clientPort = downConn.remotePort;
        pair.serverIP = downConn.localIP;
        pair.serverPort = downConn.localPort;
        pair.downstreamKey = downstream->key;
        pair.phase = PairPhase::Waiting;

        ctx->clientIP = pair.clientIP;
        ctx->clientPort = pair.clientPort;
        ctx->serverIP = pair.serverIP;
        ctx->serverPort = pair.serverPort;

        pair.upstreamKey = snet::layers::hash5Tuple(pair.serverIP,
                                                    pair.clientIP,
                                                    pair.serverPort,
                                                    pair.clientPort,
                                                    snet::layers::IPProto::Code::TCP,
                                                    /*directionUnique=*/false);

        ctx->downstreamKey = pair.downstreamKey;
        ctx->upstreamKey = pair.upstreamKey;

        CSK_LOG_WARNING("Acceptor: downstream accepted %s:%u -> %s:%u "
                      "dk=%x uk=%x",
                      pair.clientIP.toString().c_str(),
                      pair.clientPort,
                      pair.serverIP.toString().c_str(),
                      pair.serverPort,
                      pair.downstreamKey,
                      pair.upstreamKey);
    }

    /// Открыть upstream. Вызывается consumer'ом после решения.
    /// Идемпотентно: повторный вызов для уже открытой пары — no-op.
    void openUpstream(Session* downstream)
    {
        auto* downCtx = mgr_->template getContext<ProxyContext>(downstream);
        auto* downConn = mgr_->template getContext<TcpConnection>(downstream);
        if (!downCtx || !downCtx->pair || !downConn)
            return;

        auto& pair = *downCtx->pair;
        if (pair.phase != PairPhase::Waiting && pair.phase != PairPhase::Probing)
            return; // уже открыт

        // Создаём upstream-сессию.
        auto* upSession = mgr_->findOrCreate(pair.upstreamKey);
        if (!upSession)
        {
            CSK_LOG_ERROR("Acceptor: cannot create upstream");
            return;
        }

        mgr_->setSessionFlag(downstream, SessionManagerType::FlagProtected);

        auto* upCtx = mgr_->template getContext<ProxyContext>(upSession);
        if (!upCtx)
        {
            CSK_LOG_ERROR("Acceptor: upstream ProxyContext missing");
            return;
        }

        upCtx->pair = downCtx->pair;
        upCtx->isUpstream = true;
        upCtx->downstreamKey = pair.downstreamKey;
        upCtx->upstreamKey = pair.upstreamKey;
        upCtx->clientIP = pair.clientIP;
        upCtx->clientPort = pair.clientPort;
        upCtx->serverIP = pair.serverIP;
        upCtx->serverPort = pair.serverPort;

        auto* upConn = mgr_->template getContext<TcpConnection>(upSession);
        if (!upConn)
        {
            CSK_LOG_ERROR("Acceptor: upstream TcpConnection missing");
            return;
        }

        // С точки зрения upstream-сессии, локальный = сервер,
        // удалённый = клиент.
        upConn->localIP = pair.serverIP;
        upConn->localPort = pair.serverPort;
        upConn->remoteIP = pair.clientIP;
        upConn->remotePort = pair.clientPort;

        // Активное открытие.
        const uint32_t iss = nextIss();
        auto out = snet::tcp::TcpStateMachine::onActiveOpen(*upConn, iss);
        if (out.type == snet::tcp::TcpOutput::Type::Send)
        {
            upConn->pendingOutput = out;
            upConn->hasPendingOutput = true;
        }

        if (tx_)
            tx_->pump(upSession);

        mgr_->clearSessionFlag(downstream, SessionManagerType::FlagProtected);

        CSK_LOG_DEBUG("Acceptor: upstream SYN sent, uk=%x, iss=%u", pair.upstreamKey, iss);
    }

    void onReject(Session*, TcpConnection&) override
    {
    }

private:
    uint32_t nextIss()
    {
        std::uniform_int_distribution<uint32_t> dist;
        return dist(rng_);
    }

    SessionManagerType* mgr_;
    TransmitHandler* tx_;
    std::mt19937 rng_;
};

} // namespace snet::proxy