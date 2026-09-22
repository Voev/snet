// tcp_transmit_handler.hpp
#pragma once

#include <algorithm>
#include <cstdint>
#include <cstddef>

#include <snet/layers/packet.hpp>
#include <snet/layers/in_memory_packet.hpp>
#include <snet/layers/packet_builder.hpp>
#include <snet/layers/packet_sink.hpp>
#include <snet/layers/l3/ip_address.hpp>

#include <snet/session/session_handler.hpp>
#include <snet/session/session_manager.hpp>

#include <snet/tcp/tcp_state_machine.hpp>
#include <snet/tcp/tcp_stream.hpp>

#include <casket/log/log.hpp>

namespace snet::tcp
{

struct TcpTransmitHandlerConfig
{
    /// Send pending data automatically when new data appears in txRing
    /// or when an ACK opens the window.
    bool autoPumpOnAck{true};

    /// Max segments per single pump call.
    /// 0 = unlimited (drain until window closes).
    uint32_t maxSegmentsPerPump{1};

    /// Send FIN automatically when peer closed and we've drained
    /// (CLOSE_WAIT → LAST_ACK).
    bool autoFinOnCloseWait{false};

    /// Send RST on abort.
    bool sendRstOnAbort{true};

    /// TTL for outgoing IP packets.
    uint8_t ttl{64};
};

/// @brief TX-side handler — drains txRing into TCP segments.
///
/// Symmetric to TcpReceiveHandler (RX side).
///
/// Owns a TxRingPool; acquires/releases rings per session.
///
/// Responsibilities:
///   - Own TxRingPool.
///   - createContext: acquire TX ring, install into TcpConnection.
///   - destroyContext: return TX ring to pool.
///   - Emit pending output from FSM (SYN-ACK, ACK, RST, FIN) —
///     stored in TcpConnection::pendingOutput by listener/receiver.
///   - Drain txRing into segments (pumpPendingData).
///   - Provide API: sendData / flush / close / abort.
///   - Handle retransmit timer (onRetransmitTimeout).
///   - Handle TIME_WAIT expiry (onTimeWaitExpired).
///
/// This is the ONLY handler that builds and transmits packets.
///
/// Thread model: single-thread per handler instance.
template <typename SessionManagerType>
class TcpTransmitHandler : public session::ISessionHandler<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;
    using TcpConnection = snet::tcp::TcpConnection;

    static constexpr size_t MAX_PACKET_SIZE = 65536;

    TcpTransmitHandler(snet::layers::IPacketSink* sink, TxRingPool* txPool, TcpTransmitHandlerConfig config = {})
        : sink_(sink)
        , txPool_(txPool)
        , config_(config)
        , packet_(MAX_PACKET_SIZE)
    {
    }

    const char* name() const override
    {
        return "TcpTransmitHandler";
    }

    /// @brief Acquires a TX ring from the pool and installs it into
    ///        the session's TcpConnection.
    bool createContext(Session* session) override
    {
        if (!session)
            return false;

        auto* conn = this->template getContext<TcpConnection>(session);
        if (!conn)
        {
            conn = this->template allocateContext<TcpConnection>();
            if (!conn)
            {
                CSK_LOG_ERROR("TcpTransmit: cannot allocate TcpConnection");
                return false;
            }

            conn->reset();

            if (!this->template setContext<TcpConnection>(session, conn))
            {
                this->template deallocateContext<TcpConnection>(conn);
                CSK_LOG_ERROR("TcpTransmit: cannot set TcpConnection");
                return false;
            }
        }

        if (conn->txRing != nullptr)
            return true;

        if (!txPool_)
        {
            CSK_LOG_ERROR("TcpTransmit: no TX pool configured");
            return false;
        }

        TxRingBuffer* ring = txPool_->acquire();
        if (!ring)
        {
            CSK_LOG_WARNING("TcpTransmit: TX pool exhausted (capacity=%zu)", txPool_->capacity());
            return false;
        }

        // FixedObjectPool doesn't reset on acquire — do it manually
        ring->reset();

        conn->txRing = ring;
        conn->txRingOwnedByTransmit = true;

        CSK_LOG_DEBUG("TcpTransmit: TX ring acquired for session");
        return true;
    }

    bool destroyContext(Session* session) override
    {
        if (!session)
            return false;

        auto* conn = this->template getContext<TcpConnection>(session);
        if (!conn)
            return true;

        if (conn->txRing && conn->txRingOwnedByTransmit && txPool_)
        {
            conn->txRing->reset();
            txPool_->release(conn->txRing);
            conn->txRing = nullptr;
            conn->txRingOwnedByTransmit = false;

            CSK_LOG_DEBUG("TcpTransmit: TX ring returned to pool");
        }

        return true;
    }

    layers::PacketStatus processPacket(Session* session, layers::Packet* packet, layers::PacketStatus status) override
    {
        if (!session || !packet)
            return this->passToNext(session, packet, layers::PacketStatus::Error_NoMemory);

        auto* conn = this->template getContext<TcpConnection>(session);
        if (!conn)
            return this->passToNext(session, packet, layers::PacketStatus::Error_NoContext);

        if (conn->closed)
            return this->passToNext(session, packet, layers::PacketStatus::Ignore_PacketOfClosedFlow);

        // Emit pending output from FSM (SYN-ACK, ACK, RST, FIN)
        // Listener/Receiver store pendingOutput; we are the only one who actually emits it.
        if (conn->hasPendingOutput)
        {
            auto out = conn->pendingOutput;
            conn->pendingOutput = {};
            conn->hasPendingOutput = false;

            if (out.type == TcpOutput::Type::Close)
            {
                conn->closed = true;
                return this->passToNext(session, packet, layers::PacketStatus::Ignore_PacketOfClosedFlow);
            }

            if (out.type == TcpOutput::Type::Send || out.type == TcpOutput::Type::SendReset)
            {
                if (emit(conn, out) && out.type == TcpOutput::Type::Send)
                {
                    // Only advance seq numbers after successful transmit
                    TcpStateMachine::onSegmentSent(*conn, out);
                }
            }
        }

        // Pump pending data from txRing
        if (config_.autoPumpOnAck && conn->inEstablished() && conn->txRing && conn->txRing->pending() > 0)
        {
            pumpPendingData(conn);
        }

        // Auto-FIN after peer close
        if (config_.autoFinOnCloseWait && conn->state == TcpState::CloseWait && !conn->finSent && conn->txRing &&
            conn->txRing->pending() == 0)
        {
            closeConnection(session);
        }

        return this->passToNext(session, packet, status);
    }

    /// @brief Application writes data — buffered and flushed.
    /// @return Bytes accepted (may be < len if txRing full).
    size_t sendData(Session* session, const uint8_t* data, size_t len)
    {
        auto* conn = this->template getContext<TcpConnection>(session);
        if (!conn || conn->closed || !conn->txRing)
            return 0;
        if (!conn->inEstablished())
            return 0;

        const size_t accepted = conn->txRing->write(data, len);
        if (accepted == 0)
            return 0;

        pumpPendingData(conn);
        return accepted;
    }

    /// @brief Explicit flush of pending txRing data.
    /// @return Bytes actually sent.
    size_t flush(Session* session)
    {
        auto* conn = this->template getContext<TcpConnection>(session);
        if (!conn || conn->closed || !conn->txRing)
            return 0;
        return pumpPendingData(conn);
    }

    /// Pending (not yet sent) bytes in txRing.
    size_t pending(Session* session) const
    {
        auto* conn = this->template getContext<TcpConnection>(session);
        return (conn && conn->txRing) ? conn->txRing->pending() : 0;
    }

    /// Unacknowledged (sent but not ACKed) bytes.
    size_t unacked(Session* session) const
    {
        auto* conn = this->template getContext<TcpConnection>(session);
        return (conn && conn->txRing) ? conn->txRing->unacked() : 0;
    }

    /// Free space in txRing.
    size_t freeSpace(Session* session) const
    {
        auto* conn = this->template getContext<TcpConnection>(session);
        return (conn && conn->txRing) ? conn->txRing->freeSpace() : 0;
    }

    /// @brief Application closes connection — flush + FIN.
    void closeConnection(Session* session)
    {
        auto* conn = this->template getContext<TcpConnection>(session);
        if (!conn || conn->closed)
            return;

        // Flush pending data first
        if (conn->txRing && conn->txRing->pending() > 0)
            pumpPendingData(conn);

        auto out = TcpStateMachine::onAppClose(*conn);
        if (out.type == TcpOutput::Type::Send)
        {
            if (emit(conn, out))
                TcpStateMachine::onSegmentSent(*conn, out);
        }
    }

    /// @brief Application aborts — send RST.
    void abortConnection(Session* session)
    {
        auto* conn = this->template getContext<TcpConnection>(session);
        if (!conn || conn->closed)
            return;

        if (!config_.sendRstOnAbort)
        {
            conn->closed = true;
            return;
        }

        auto out = TcpStateMachine::onAppAbort(*conn);
        if (out.type == TcpOutput::Type::SendReset || out.type == TcpOutput::Type::Send)
        {
            emit(conn, out);
        }
    }

    /// @brief RTO fired — retransmit from sndUna.
    void onRetransmitTimeout(Session* session)
    {
        auto* conn = this->template getContext<TcpConnection>(session);
        if (!conn || conn->closed)
            return;

        if (!conn->inEstablished() && conn->state != TcpState::SynSent && conn->state != TcpState::SynReceived)
            return;

        auto out = TcpStateMachine::onRetransmitTimeout(*conn);

        if (out.type == TcpOutput::Type::Send)
        {
            if (emit(conn, out))
            {
                // NOTE: for retransmit we do NOT call onSegmentSent,
                // because sndNxt must not advance (data was already sent).
                // However, onSegmentSent also bumps stats — we want those.
                // See TcpStateMachine::onSegmentSent doc.
                //
                // The current FSM's onSegmentSent does NOT check for
                // retransmit — it always advances. To make retransmit
                // safe, we must guard here:
                const uint32_t nextToSend =
                    conn->txRing ? conn->txRing->seqBase() +
                                       static_cast<uint32_t>(conn->txRing->pending() > 0 ? 0 : 0) // placeholder
                                 : 0;
                (void)nextToSend;

                // Simple heuristic: if out.seq < conn->sndNxt, it's a
                // retransmit, so do not advance sndNxt.
                // We still bump counters.
                if (out.seq == conn->sndNxt)
                {
                    TcpStateMachine::onSegmentSent(*conn, out);
                }
                else
                {
                    // Retransmit — bump stats only
                    conn->retransmits++;
                    conn->packetsSent++;
                    conn->bytesSent += out.payloadLen;
                }
            }
        }

        CSK_LOG_DEBUG("TcpTransmit: retransmit (state=%s, sndUna=%u)",
                      std::string(tcpStateName(conn->state)).c_str(),
                      conn->sndUna);
    }

    /// @brief TIME_WAIT expired — close session.
    void onTimeWaitExpired(Session* session)
    {
        auto* conn = this->template getContext<TcpConnection>(session);
        if (!conn)
            return;

        auto out = TcpStateMachine::onTimeWaitExpired(*conn);
        if (out.type == TcpOutput::Type::Close)
            conn->closed = true;
    }

private:
    size_t pumpPendingData(TcpConnection* conn)
    {
        if (!conn || conn->closed || !conn->txRing)
            return 0;

        auto& ring = *conn->txRing;
        if (!ring.initialized() || ring.pending() == 0)
            return 0;

        size_t totalSent = 0;
        uint32_t segmentsSent = 0;

        while (true)
        {
            // Effective window = min(cwnd_bytes, peer window, MSS)
            const size_t cwndBytes = static_cast<size_t>(conn->cwnd) * conn->mss;
            const size_t sndWnd = static_cast<size_t>(conn->sndWnd);

            const size_t effective = std::min({cwndBytes, sndWnd, static_cast<size_t>(conn->mss)});

            if (effective == 0)
            {
                CSK_LOG_DEBUG("TcpTransmit: zero window "
                              "(sndWnd=%zu, cwnd=%zu)",
                              sndWnd,
                              cwndBytes);
                break;
            }

            // Zero-copy peek of txRing
            auto [data, len] = ring.peek();
            if (!data || len == 0)
                break;

            const size_t chunk = std::min(len, effective);

            // Build output directive (PSH|ACK, next seq)
            TcpOutput out = TcpOutput::sendData(conn->sndNxt, conn->rcvNxt, conn->rcvWnd, data, chunk);

            if (!emit(conn, out))
                break;

            // Advance sequence + ring read position
            TcpStateMachine::onSegmentSent(*conn, out);
            ring.advance(chunk);

            totalSent += chunk;
            segmentsSent++;

            CSK_LOG_DEBUG("TcpTransmit: sent %zu bytes, seq=%u, ack=%u, "
                          "cwnd=%u, sndWnd=%u",
                          chunk,
                          out.seq,
                          out.ack,
                          conn->cwnd,
                          conn->sndWnd);

            if (config_.maxSegmentsPerPump != 0 && segmentsSent >= config_.maxSegmentsPerPump)
                break;
        }

        return totalSent;
    }

    /// @brief Builds IP+TCP packet into the reusable InMemoryPacket
    ///        and hands it to the sink.
    /// @return true on successful transmit.
    bool emit(TcpConnection* conn, const TcpOutput& out)
    {
        using namespace snet::layers;

        switch (out.type)
        {
        case TcpOutput::Type::None:
            return false;

        case TcpOutput::Type::Close:
            conn->closed = true;
            CSK_LOG_DEBUG("TcpTransmit: connection closed (state=%s)", std::string(tcpStateName(conn->state)).c_str());
            return false;

        case TcpOutput::Type::Send:
        case TcpOutput::Type::SendReset:
            break;
        }

        if (!sink_)
        {
            CSK_LOG_ERROR("TcpTransmit: no sink configured");
            return false;
        }

        // Build IP + TCP (no Ethernet — sink adds L2)
        //
        // PacketBuilder ctor calls packet_.asPacket()->reset(),
        // so layers are cleared. The InMemoryPacket buffer is reused.
        snet::layers::PacketBuilder<snet::layers::InMemoryPacket> builder(&packet_);
        constexpr uint16_t IP_HDR_LEN = 20;
        constexpr uint16_t TCP_HDR_LEN = 20;
        const uint16_t ipTotalLen = IP_HDR_LEN + TCP_HDR_LEN + static_cast<uint16_t>(out.payloadLen);
        constexpr uint16_t IP_FLAG_DF = 0x4000; // Don't Fragment

        builder.ipv4()
            .apply(setVerIhl, 4, 5)
            .set(&ipv4_header::tos, 0)
            .set(&ipv4_header::tot_len, casket::host_to_be(ipTotalLen))
            .set(&ipv4_header::id, 0)
            .set(&ipv4_header::frag_off, casket::host_to_be(IP_FLAG_DF))
            .set(&ipv4_header::ttl, config_.ttl)
            .set(&ipv4_header::protocol, IPProto::TCP)
            .set(&ipv4_header::saddr, conn->localIP.toIPv4().toNetwork())
            .set(&ipv4_header::daddr, conn->remoteIP.toIPv4().toNetwork())
            .build();

        builder.tcp()
            .set(&tcp_header::source, casket::host_to_be(conn->localPort))
            .set(&tcp_header::dest, casket::host_to_be(conn->remotePort))
            .set(&tcp_header::seq, casket::host_to_be(out.seq))
            .set(&tcp_header::ack_seq, casket::host_to_be(out.ack))
            .apply(setTcpDoffFlags, uint8_t{5}, out.flags.toByte())
            .set(&tcp_header::window, casket::host_to_be(out.window))
            .set(&tcp_header::urg_ptr, 0);

        if (out.payloadLen > 0 && out.payload)
            builder.payload(out.payload, out.payloadLen);

        // build() computes IP and TCP checksums and sets raw data
        auto* built = builder.build();
        if (!built)
        {
            CSK_LOG_ERROR("TcpTransmit: build() failed");
            return false;
        }

        // Sink handles L2 framing (Ethernet, ARP, etc.).
        const bool ok = sink_->transmit(built->asPacket());
        if (!ok)
        {
            CSK_LOG_WARNING("TcpTransmit: transmit failed (%zu bytes)", built->getLen());
        }

        return ok;
    }

private:
    snet::layers::IPacketSink* sink_{nullptr};
    TxRingPool* txPool_{nullptr};
    TcpTransmitHandlerConfig config_;

    /// Single reusable packet — buffer allocated once in ctor.
    /// Reused for every outgoing segment.
    snet::layers::InMemoryPacket packet_;
};

} // namespace snet::tcp