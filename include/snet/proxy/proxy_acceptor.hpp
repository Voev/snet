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

/// Split-proxy acceptor.
///
/// Invoked by TcpReceiveHandler when a TCP connection with a client is
/// established. Does NOT open upstream immediately — it only records
/// downstream and prepares the pair. Upstream opening is initiated later,
/// from the consumer, after the decision (bypass/mitm) is made.
template <typename SessionManagerType>
class ProxyAcceptor final : public snet::tcp::IConnectionAcceptor<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;                      ///< Session type of the manager.
    using TcpConnection = snet::tcp::TcpConnection;                            ///< TCP connection type.
    using TransmitHandler = snet::tcp::TcpTransmitHandler<SessionManagerType>; ///< Transmit handler type.

    /// @param[in] mgr Session manager owning contexts and sessions.
    /// @param[in] tx  Transmit handler used to pump outgoing packets.
    ProxyAcceptor(SessionManagerType* mgr, TransmitHandler* tx, layers::IPAddress localIP)
        : mgr_(mgr)
        , tx_(tx)
        , localIP_(localIP)
        , rng_(std::random_device{}())
    {
    }

    /// Handle a newly accepted TCP connection.
    ///
    /// For downstream connections (local port 8443) builds and stores
    /// the ProxyPair in the session context, computing both direction
    /// keys. For other (upstream) connections it is a no-op that only
    /// logs and waits for the pair to be created.
    ///
    /// @param[in] downstream Accepted session.
    /// @param[in] downConn   Accepted TCP connection.
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
                                                    localIP_,
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

    /// Open the upstream connection. Called by the consumer after a decision.
    /// Idempotent: a repeated call for an already opened pair is a no-op.
    ///
    /// Creates the upstream session (if missing), mirrors pair metadata
    /// into its context, assigns server/client addresses from the upstream
    /// perspective, and sends the initial SYN with a random ISS.
    ///
    /// @param[in] downstream Downstream session whose pair should be opened.
    void openUpstream(Session* downstream)
    {
        auto* downCtx = mgr_->template getContext<ProxyContext>(downstream);
        auto* downConn = mgr_->template getContext<TcpConnection>(downstream);
        if (!downCtx || !downCtx->pair || !downConn)
            return;

        auto& pair = *downCtx->pair;
        if (pair.phase != PairPhase::Waiting && pair.phase != PairPhase::Probing)
            return; // already open

        // Create upstream session.
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

        // From the upstream session's perspective, local = server,
        // remote = client.
        upConn->localIP = localIP_;
        upConn->localPort = pair.clientPort;
        upConn->remoteIP = pair.serverIP;
        upConn->remotePort = pair.serverPort;

        // Active open.
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

    /// Handle a rejected connection. No-op.
    ///
    /// @param[in] session Rejected session (unused).
    /// @param[in] conn    Rejected TCP connection (unused).
    void onReject(Session*, TcpConnection&) override
    {
    }

private:
    /// @return A random initial send sequence number (ISS).
    uint32_t nextIss()
    {
        std::uniform_int_distribution<uint32_t> dist;
        return dist(rng_);
    }

    uint16_t nextEphemeralPort()
    {
        std::uniform_int_distribution<uint16_t> d(40000, 60000);
        return d(rng_);
    }

    SessionManagerType* mgr_; ///< Session manager (not owned).
    TransmitHandler* tx_;     ///< Transmit handler (not owned).
    layers::IPAddress localIP_;
    std::mt19937 rng_; ///< RNG for initial sequence numbers.
};

} // namespace snet::proxy