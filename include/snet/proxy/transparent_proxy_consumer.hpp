#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>

#include <snet/session/session_manager.hpp>
#include <snet/tcp/tcp_stream.hpp>
#include <snet/tcp/tcp_transmit_handler.hpp>

#include <snet/proxy/proxy_context.hpp>
#include <snet/proxy/tls_decision_engine.hpp>
#include <snet/proxy/transparent_proxy_acceptor.hpp>

#include <snet/utils/print_hex.hpp>

#include <casket/log/log.hpp>

namespace snet::proxy
{

/// Split-proxy consumer.
///
/// Pair lifecycle:
///   1. Waiting — client TCP established, ClientHello not yet received.
///   2. ClientHello arrives → buffered in pair.bufferedClientHello,
///      SNI extracted, decision engine started.
///   3. While Probing — downstream does not relay any bytes.
///   4. Decision Bypass:
///        - open upstream;
///        - relay the ORIGINAL ClientHello to upstream as-is;
///        - then raw splice.
///   5. Decision Mitm:
///        - open upstream;
///        - build our own ClientHello to the server via serverTls;
///        - build our own ServerHello to the client via clientTls;
///        - then TLS termination.
///   6. Decision Block — RST, close.
template <typename SessionManagerType>
class TransparentProxyConsumer final : public snet::tcp::IStreamConsumer<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session; ///< Session type of the manager.
    using TcpConnection = snet::tcp::TcpConnection; ///< TCP connection type.
    using TransmitHandler = snet::tcp::TcpTransmitHandler<SessionManagerType>; ///< Transmit handler type.
    using Acceptor = TransparentProxyAcceptor<SessionManagerType>; ///< Upstream opener.
    using TlsSession = snet::tls::Session; ///< TLS session type used for MITM.

    /// @param[in] mgr      Session manager owning contexts and sessions.
    /// @param[in] tx       Transmit handler used to pump outgoing packets.
    /// @param[in] engine   Decision engine resolving SNI to a verdict.
    /// @param[in] acceptor Acceptor used to open the upstream connection.
    TransparentProxyConsumer(SessionManagerType* mgr, TransmitHandler* tx, TlsDecisionEngine* engine,
                             Acceptor* acceptor)
        : mgr_(mgr)
        , tx_(tx)
        , engine_(engine)
        , acceptor_(acceptor)
    {
    }

    /// Handle stream data arriving on a pair session.
    ///
    /// Dispatches on the pair phase: buffers ClientHello in Waiting,
    /// keeps buffering in Probing, raw-splices in Splice, terminates
    /// TLS in Mitm, and drains in Closed.
    ///
    /// @param[in] session Session the data arrived on.
    /// @param[in] side    Stream side (unused).
    /// @param[in] reader  Reader over the available stream bytes.
    void onStreamData(Session* session, int8_t /*side*/, snet::tcp::IStreamReader& reader) override
    {

        auto* ctx = mgr_->template getContext<ProxyContext>(session);
        if (!ctx || !ctx->pair)
            return;
        CSK_LOG_WARNING("onStreamData: pair=%p", static_cast<void*>(ctx ? ctx->pair.get() : nullptr));

        auto& pair = *ctx->pair;

        switch (pair.phase)
        {
        case PairPhase::Waiting:
            std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << std::endl;
            handleWaiting(session, *ctx, pair, reader);
            break;

        case PairPhase::Probing:
        {
            // Keep buffering while probe is in flight: client may retransmit
            // ClientHello or start sending early data. All of it must be
            // flushed to upstream by pushToUpstream() after the decision.
            while (reader.available() > 0)
            {
                auto [data, len] = reader.peek();
                if (!data || len == 0)
                    break;
                pair.bufferedClientHello.insert(pair.bufferedClientHello.end(), data, data + len);
                reader.consume(len);
            }
            break;
        }
        case PairPhase::Splice:
            forwardRaw(session, *ctx, pair, reader);
            break;

        case PairPhase::Mitm:
            forwardMitm(session, *ctx, pair, reader);
            break;

        case PairPhase::Closed:
            reader.consume(reader.available());
            break;
        }
    }

    /// Handle stream close on a pair session.
    ///
    /// Marks the pair Closed, closes the peer session, and prints a summary.
    ///
    /// @param[in] session Session that closed.
    /// @param[in] side    Stream side (unused).
    /// @param[in] reason  Close reason (unused).
    void onStreamClose(Session* session, int8_t /*side*/, int /*reason*/) override
    {
        auto* ctx = mgr_->template getContext<ProxyContext>(session);
        if (!ctx || !ctx->pair)
            return;

        auto& pair = *ctx->pair;
        pair.phase = PairPhase::Closed;

        // Close the peer session.
        const uint32_t otherKey = ctx->isDownstream ? pair.upstreamKey : pair.downstreamKey;
        closeOther(otherKey);

        printSummary(pair);
    }

    /// Handle a stream gap (missing bytes).
    ///
    /// @param[in] missingBytes Number of missing bytes.
    void onStreamGap(Session*, int8_t, uint32_t missingBytes) override
    {
        CSK_LOG_WARNING("TransparentProxy: gap %u bytes", missingBytes);
    }

private:
    /// Waiting phase: buffer ClientHello, determine SNI, start probe.
    /// Buffer incoming bytes, extract the SNI once available, and start
    /// the decision request, transitioning the pair to Probing.
    ///
    /// @param[in] session Pair session.
    /// @param[in] ctx     Session context.
    /// @param[in] pair    Pair state.
    /// @param[in] reader  Reader over available bytes.
    void handleWaiting(Session* session, ProxyContext& ctx, ProxyPair& pair, snet::tcp::IStreamReader& reader)
    {
        if (!ctx.isDownstream)
            return;

        // Buffer everything that arrived.
        while (reader.available() > 0)
        {
            auto [data, len] = reader.peek();
            if (!data || len == 0)
                break;
            pair.bufferedClientHello.insert(pair.bufferedClientHello.end(), data, data + len);
            reader.consume(len);
        }

        // Try to extract SNI from the buffered bytes.
        if (pair.clientSni.empty())
        {
            auto sni = std::string("test"); // extractSniFromClientHello(pair.bufferedClientHello);
            if (sni.empty())
                return; // wait for more bytes
            pair.clientSni = std::move(sni);
            CSK_LOG_DEBUG("Proxy: SNI=%s", pair.clientSni.c_str());
        }

        // Start the decision request.
        pair.phase = PairPhase::Probing;
        engine_->request(pair.clientSni,
                         pair.serverIP,
                         pair.serverPort,
                         [this, session](InspectionDecision d)
                         {
                             onDecision(session, d);
                         });
    }

    /// Decision received. Apply it.
    /// Apply a decision: Bypass → splice + flush buffered ClientHello;
    /// Mitm → open upstream + start MITM; Block → RST and close.
    ///
    /// @param[in] session Pair session.
    /// @param[in] d       Decision to apply.
    void onDecision(Session* session, InspectionDecision d)
    {
        auto* ctx = mgr_->template getContext<ProxyContext>(session);
        if (!ctx || !ctx->pair)
            return;
        auto& pair = *ctx->pair;

        pair.decision = d;

        switch (d)
        {
        case InspectionDecision::Bypass:
        {
            pair.phase = PairPhase::Splice;
            acceptor_->openUpstream(session);
            if (!pair.bufferedClientHello.empty())
            {
                pushToUpstream(session, *ctx, pair, pair.bufferedClientHello);
                pair.bufferedClientHello.clear();
            }
            break;
        }
        case InspectionDecision::Mitm:
            pair.phase = PairPhase::Mitm;
            acceptor_->openUpstream(session);
            startMitm(session, *ctx, pair);
            break;

        case InspectionDecision::Block:
            pair.phase = PairPhase::Closed;
            blockFlow(session, *ctx, pair);
            break;
        }
    }

    /// MITM session setup. Skeleton — full TLS termination logic is
    /// implemented separately; only infrastructure is set up here.
    /// Create the two TLS sessions used for MITM (client-facing and
    /// server-facing). Actual handshake construction is not done here.
    ///
    /// @param[in] session Pair session.
    /// @param[in] ctx     Session context.
    /// @param[in] pair    Pair state.
    void startMitm(Session* session, ProxyContext& ctx, ProxyPair& pair)
    {
        (void)session;
        (void)ctx;

        // Create two tls::Session instances working in active mode.
        pair.clientTls = std::make_unique<TlsSession>(pair.pool);
        pair.clientTls->setMonitor(false);

        pair.serverTls = std::make_unique<TlsSession>(pair.pool);
        pair.serverTls->setMonitor(false);

        // TODO: build ServerHello/Certificate/Finished for the client
        //       and ClientHello for the server. This is a separate,
        //       substantial topic.
        //
        // See Session::constructClientHello / constructServerHello
        // (the latter is not in the public API — ServerHello must be
        //  generated manually or added to Session).

        CSK_LOG_INFO("Proxy: MITM enabled for SNI=%s", pair.clientSni.c_str());
    }

    /// Bypass: relay bytes as-is.
    /// Move bytes from the reader into the peer connection's txRing
    /// without any modification.
    ///
    /// @param[in] session Pair session (unused).
    /// @param[in] ctx     Session context.
    /// @param[in] pair    Pair state (byte counters updated).
    /// @param[in] reader  Reader over available bytes.
    void forwardRaw(Session* session, ProxyContext& ctx, ProxyPair& pair, snet::tcp::IStreamReader& reader)
    {
        (void)session;

        // Determine the destination session.
        const uint32_t dstKey = ctx.isDownstream ? pair.upstreamKey : pair.downstreamKey;
        auto* dstSession = mgr_->find(dstKey);
        if (!dstSession)
            return;

        auto* dstConn = mgr_->template getContext<TcpConnection>(dstSession);
        if (!dstConn || dstConn->closed || !dstConn->txRing)
            return;

        while (reader.available() > 0)
        {
            const size_t free = dstConn->txRing->freeSpace();
            if (free == 0)
                break;

            auto [data, len] = reader.peek();
            if (!data || len == 0)
                break;

            utils::printHex(std::cout, {data, len}, "TCP stream");

            const size_t chunk = std::min(len, free);
            const size_t written = dstConn->txRing->write(data, chunk);
            reader.consume(written);

            if (ctx.isDownstream)
                pair.bytesToServer += written;
            else
                pair.bytesToClient += written;

            if (written < chunk)
                break;
        }

        if (tx_)
            tx_->pump(dstSession);
    }

    /// MITM: decrypt, process, re-encrypt.
    /// Skeleton — the full logic is more involved; only structure here.
    /// Feed the reader into the appropriate TLS session, process records,
    /// and emit outgoing bytes to the peer. Currently a placeholder that
    /// drains the reader.
    ///
    /// @param[in] session Pair session (unused).
    /// @param[in] ctx     Session context (unused).
    /// @param[in] pair    Pair state (unused).
    /// @param[in] reader  Reader over available bytes.
    void forwardMitm(Session* session, ProxyContext& ctx, ProxyPair& pair, snet::tcp::IStreamReader& reader)
    {
        (void)session;
        (void)ctx;
        (void)pair;
        // TODO:
        //   1. Feed the reader into pair.clientTls (or serverTls depending on ctx).
        //   2. processPendingRecords with a handler:
        //        - ApplicationData → decrypt → pass to the other session.
        //        - Handshake → handle (KeyUpdate, etc.).
        //   3. Take outgoing from the other session, write into its txRing.
        //
        // For now — nothing; MITM is implemented as a separate step.
        reader.consume(reader.available());
    }

    /// Relay an arbitrary buffer into the upstream txRing.
    /// Used on bypass to send the original ClientHello.
    /// Write the given buffer into the upstream txRing (used to flush
    /// the original ClientHello after a Bypass decision).
    ///
    /// @param[in] session Pair session (unused).
    /// @param[in] ctx     Session context (unused).
    /// @param[in] pair    Pair state (byte counters updated).
    /// @param[in] bytes   Bytes to relay.
    void pushToUpstream(Session* session, ProxyContext& ctx, ProxyPair& pair, const std::vector<uint8_t>& bytes)
    {
        (void)session;
        (void)ctx;

        if (bytes.empty())
            return;

        const uint32_t dstKey = ctx.isDownstream ? pair.upstreamKey : pair.downstreamKey;
        auto* dstSession = mgr_->find(dstKey);
        if (!dstSession)
            return;

        auto* dstConn = mgr_->template getContext<TcpConnection>(dstSession);
        if (!dstConn || !dstConn->txRing)
            return;

        // Write whatever fits. The remainder will be sent later — but
        // since ClientHello is usually < MSS, no overflow is expected.
        size_t off = 0;
        while (off < bytes.size())
        {
            const size_t free = dstConn->txRing->freeSpace();
            if (free == 0)
                break;

            const size_t chunk = std::min(free, bytes.size() - off);
            const size_t w = dstConn->txRing->write(bytes.data() + off, chunk);
            off += w;
            pair.bytesToServer += w;
            if (w < chunk)
                break;
        }

        if (tx_)
            tx_->pump(dstSession);
    }

    /// Abort the flow with a RST and close the session.
    ///
    /// @param[in] session Session to abort.
    /// @param[in] ctx     Session context (unused).
    /// @param[in] pair    Pair state (unused).
    void blockFlow(Session* session, ProxyContext& ctx, ProxyPair& pair)
    {
        auto* conn = mgr_->template getContext<TcpConnection>(session);
        if (conn)
        {
            auto out = snet::tcp::TcpStateMachine::onAppAbort(*conn);
            if (out.type == snet::tcp::TcpOutput::Type::SendReset)
            {
                conn->pendingOutput = out;
                conn->hasPendingOutput = true;
                if (tx_)
                    tx_->pump(session);
            }
        }
        (void)ctx;
        (void)pair;
    }

    /// Close the session identified by the given key (gracefully or RST).
    ///
    /// @param[in] key Session key of the peer to close.
    void closeOther(uint32_t key)
    {
        auto* other = mgr_->find(key);
        if (!other)
            return;

        auto* otherConn = mgr_->template getContext<TcpConnection>(other);
        if (!otherConn || otherConn->closed)
            return;

        auto out = snet::tcp::TcpStateMachine::onAppClose(*otherConn);
        if (out.type == snet::tcp::TcpOutput::Type::Send || out.type == snet::tcp::TcpOutput::Type::SendReset)
        {
            otherConn->pendingOutput = out;
            otherConn->hasPendingOutput = true;
            if (tx_)
                tx_->pump(other);
        }
    }

    // Extract SNI from the buffered ClientHello.
    // Wrapper: locates the TLS record carrying a handshake ClientHello,
    // then calls extractSni over the extensions.
    /// Extract the SNI from a buffered ClientHello.
    ///
    /// @param[in] buf Buffered ClientHello bytes.
    /// @return SNI string, or empty if not present / not yet complete.
    static std::string extractSniFromClientHello(const std::vector<uint8_t>& buf);

    /// Print a short summary of the pair (endpoints, SNI, decision, bytes).
    ///
    /// @param[in] pair Pair state to summarize.
    void printSummary(const ProxyPair& pair) const
    {
        printf("\n═══ TLS proxy session summary ═══\n");
        printf("  %s:%u <-> %s:%u\n",
               pair.clientIP.toString().c_str(),
               pair.clientPort,
               pair.serverIP.toString().c_str(),
               pair.serverPort);
        printf("  SNI:    %s\n", pair.clientSni.empty() ? "(none)" : pair.clientSni.c_str());
        printf("  Decision: %s\n",
               pair.decision == InspectionDecision::Mitm    ? "MITM"
               : pair.decision == InspectionDecision::Block ? "Block"
                                                            : "Bypass");
        printf("  Bytes:  c->s %lu, s->c %lu\n", pair.bytesToServer, pair.bytesToClient);
        printf("═════════════════════════════════\n\n");
    }

    SessionManagerType* mgr_;    ///< Session manager (not owned).
    TransmitHandler* tx_;        ///< Transmit handler (not owned).
    TlsDecisionEngine* engine_;  ///< Decision engine (not owned).
    Acceptor* acceptor_;         ///< Acceptor used to open upstream (not owned).
};

} // namespace snet::proxy