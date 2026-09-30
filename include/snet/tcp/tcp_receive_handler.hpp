#pragma once

#include <cstdint>
#include <chrono>

#include <snet/layers/packet.hpp>
#include <snet/layers/l3/ip_address.hpp>

#include <snet/session/session_handler.hpp>
#include <snet/session/session_manager.hpp>

#include <snet/tcp/tcp_state_machine.hpp>
#include <snet/tcp/tcp_stream.hpp>

#include <casket/log/log.hpp>

namespace snet::tcp
{

/// @brief Zero-copy reader over RxRingBuffer.
class RxStreamReader : public IStreamReader
{
public:
    explicit RxStreamReader(RxRingBuffer* ring)
        : ring_(ring)
    {
    }

    std::pair<const uint8_t*, size_t> peek() override
    {
        return ring_->peek();
    }
    size_t read(uint8_t* out, size_t maxLen) override
    {
        return ring_->read(out, maxLen);
    }
    void consume(size_t n) override
    {
        ring_->consume(n);
    }
    size_t available() const override
    {
        return ring_->available();
    }

private:
    RxRingBuffer* ring_;
};

struct TcpReceiveHandlerConfig
{
    bool autoAck{true};

    /// Replay mode: passive observation of an existing TCP flow (pcap).
    /// In this mode SYN/SYN-ACK initialize the FSM from observed seqs
    /// and no packets are emitted.
    bool replayMode{false};

    /// Port that identifies the server side (used to pick context index
    /// when the flow is new).
    uint16_t proxyPort{443};
};

/// @brief RX-side handler — feeds incoming TCP segments to the FSM.
///
/// Does NOT create contexts — they must be created by
/// TcpConnectionCtxFactory (installed via SessionPipeline::addFactory).
///
/// Contexts used:
///   - TcpConnection[0] — client → server direction
///   - TcpConnection[1] — server → client direction
///
/// The correct index is determined from the 5-tuple on each packet.
template <typename SessionManagerType>
class TcpReceiveHandler : public session::ISessionHandler<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;
    using TcpConnection = snet::tcp::TcpConnection;
    using Acceptor = IConnectionAcceptor<SessionManagerType>;
    using Consumer = IStreamConsumer<SessionManagerType>;

    static constexpr int8_t kClientSide = 0;
    static constexpr int8_t kServerSide = 1;
    static constexpr int8_t kSideUnknown = -1;

    TcpReceiveHandler(Acceptor* acceptor, Consumer* consumer, TcpReceiveHandlerConfig config = {})
        : acceptor_(acceptor)
        , consumer_(consumer)
        , config_(config)
    {
    }

    void setConsumer(Consumer* c)
    {
        consumer_ = c;
    }
    void setAcceptor(Acceptor* a)
    {
        acceptor_ = a;
    }

    const char* name() const override
    {
        return "TcpReceiveHandler";
    }

    // ============================================================
    // Packet processing
    // ============================================================

    layers::PacketStatus processPacket(Session* session, layers::Packet* packet, layers::PacketStatus status) override
    {
        if (!session || !packet)
            return this->passToNext(session, packet, layers::PacketStatus::Error_NoMemory);

        snet::layers::IPAddress srcIP, dstIP;
        snet::layers::TCPHeader hdr;
        const snet::layers::LayerInfo* tcpLayer = nullptr;

        if (!extractPacketInfo(packet, srcIP, dstIP, hdr, tcpLayer))
            return this->passToNext(session, packet, layers::PacketStatus::NonTcpPacket);

        return config_.replayMode ? processReplay(session, packet, srcIP, dstIP, hdr, tcpLayer, status)
                                  : processLive(session, packet, srcIP, hdr, tcpLayer, status);
    }

private:
    // ============================================================
    // Replay mode (pcap): passive observation
    // ============================================================

    layers::PacketStatus processReplay(Session* session, layers::Packet* packet, const snet::layers::IPAddress& srcIP,
                                       const snet::layers::IPAddress& dstIP, const snet::layers::TCPHeader& hdr,
                                       const snet::layers::LayerInfo* tcpLayer, layers::PacketStatus status)
    {
        // ─── Pure SYN: initialize client-side (ctx 0) ───
        if (hdr.isSYN() && !hdr.isACK())
        {
            auto* conn = this->template getContext<TcpConnection>(session, kClientSide);
            if (!conn)
            {
                CSK_LOG_ERROR("Replay: ctx[0] missing — factory not installed?");
                return this->passToNext(session, packet, layers::PacketStatus::Error_NoContext);
            }

            // Set endpoints on first packet of this direction
            if (conn->remotePort == 0)
            {
                conn->localIP = dstIP;
                conn->localPort = hdr.dstPort();
                conn->remoteIP = srcIP;
                conn->remotePort = hdr.srcPort();
            }

            const bool isNew = (conn->state == TcpState::Closed) || conn->closed || (conn->irs != hdr.seqNum());

            if (isNew)
            {
                conn->irs = hdr.seqNum();
                conn->rcvNxt = conn->irs + 1;
                conn->state = TcpState::SynReceived;
                conn->closed = false;
                conn->finSent = conn->finReceived = conn->resetSent = false;
                conn->lastActivity = std::chrono::steady_clock::now();

                if (conn->rxRing)
                    conn->rxRing->initAt(conn->rcvNxt);
                if (conn->txRing)
                    conn->txRing->initAt(hdr.seqNum() /* placeholder */);

                CSK_LOG_DEBUG("Replay: SYN (new) ctx[0] clientISN=%u", conn->irs);
            }
            else
            {
                CSK_LOG_DEBUG("Replay: SYN (retransmit) ctx[0] clientISN=%u", conn->irs);
            }

            return this->passToNext(session, packet, layers::PacketStatus::TcpMessageHandled);
        }

        // ─── SYN-ACK: initialize server-side (ctx 1) ───
        if (hdr.isSYN() && hdr.isACK())
        {
            auto* conn = this->template getContext<TcpConnection>(session, kServerSide);
            if (!conn)
            {
                CSK_LOG_ERROR("Replay: ctx[1] missing — factory not installed?");
                return this->passToNext(session, packet, layers::PacketStatus::Error_NoContext);
            }

            // Set endpoints on first packet of this direction
            if (conn->remotePort == 0)
            {
                conn->localIP = dstIP;
                conn->localPort = hdr.dstPort();
                conn->remoteIP = srcIP;
                conn->remotePort = hdr.srcPort();
            }

            if (conn->state == TcpState::Established)
            {
                CSK_LOG_DEBUG("Replay: SYN-ACK (retransmit) ctx[1] — ignored");
                return this->passToNext(session, packet, layers::PacketStatus::TcpMessageHandled);
            }

            conn->irs = hdr.seqNum();
            conn->rcvNxt = conn->irs + 1;
            conn->state = TcpState::Established;
            conn->lastActivity = std::chrono::steady_clock::now();

            if (conn->rxRing)
                conn->rxRing->initAt(conn->rcvNxt);

            CSK_LOG_DEBUG("Replay: SYN-ACK ctx[1] serverISN=%u, ESTABLISHED", conn->irs);

            if (acceptor_)
                acceptor_->onAccept(session, *conn);

            return this->passToNext(session, packet, layers::PacketStatus::TcpMessageHandled);
        }

        // ─── ACK от клиента: ctx[0] SynReceived → Established ───
        if (hdr.isACK() && !hdr.isSYN() && !hdr.isRST())
        {
            auto* conn0 = this->template getContext<TcpConnection>(session, kClientSide);
            if (conn0 && conn0->state == TcpState::SynReceived)
            {
                // Смотрим serverISN из ctx[1]
                auto* conn1 = this->template getContext<TcpConnection>(session, kServerSide);
                if (conn1 && conn1->irs != 0)
                {
                    const uint32_t serverISN = conn1->irs;

                    // ACK должен подтвердить наш SYN: ack = serverISN + 1
                    if (hdr.ackNum() == serverISN + 1)
                    {
                        conn0->iss = serverISN;
                        conn0->sndUna = serverISN + 1;
                        conn0->sndNxt = serverISN + 1;
                        conn0->sndWnd = hdr.window();
                        conn0->state = TcpState::Established;
                        conn0->lastActivity = std::chrono::steady_clock::now();

                        if (conn0->txRing)
                            conn0->txRing->initAt(conn0->sndNxt);

                        CSK_LOG_DEBUG("Replay: ACK from client, "
                                      "ctx[0] SynReceived → Established "
                                      "(serverISN=%u)",
                                      serverISN);
                    }
                }
            }
        }

        // ─── Other packets: dispatch to the correct context ───
        const int8_t idx = determineContextIndex(session, srcIP, hdr.srcPort());
        if (idx < 0)
        {
            CSK_LOG_DEBUG("Replay: cannot determine ctx for %s:%u", srcIP.toString().c_str(), hdr.srcPort());
            return this->passToNext(session, packet, layers::PacketStatus::Error_PacketDoesNotMatchFlow);
        }

        auto* conn = this->template getContext<TcpConnection>(session, idx);
        if (!conn || conn->state == TcpState::Closed)
        {
            return this->passToNext(session, packet, layers::PacketStatus::Ignore_PacketOfClosedFlow);
        }

        if (!conn->rxRing)
        {
            CSK_LOG_WARNING("Replay: no RX ring for ctx=%d", idx);
            return this->passToNext(session, packet, status);
        }

        TcpSegment seg;
        seg.flags = snet::layers::TcpFlags::fromByte(hdr.flagsByte());
        seg.seq = hdr.seqNum();
        seg.ack = hdr.ackNum();
        seg.window = hdr.window();
        seg.payload = packet->getPayloadData(tcpLayer);
        seg.payloadLen = packet->getPayloadSize(tcpLayer);

        auto result = TcpStateMachine::onRxSegment(*conn, seg);

        // Replay mode: do not emit anything.
        // pendingOutput is intentionally ignored.

        if (result.deliverToApp && consumer_)
        {
            RxStreamReader reader{conn->rxRing};
            consumer_->onStreamData(session, idx, reader);
        }

        if (result.closed && consumer_)
        {
            consumer_->onStreamClose(session, idx, 0);
        }

        return this->passToNext(
            session,
            packet,
            result.closed ? layers::PacketStatus::Ignore_PacketOfClosedFlow : layers::PacketStatus::TcpMessageHandled);
    }

    // ============================================================
    // Live mode (real network)
    // ============================================================

    layers::PacketStatus processLive(Session* session, layers::Packet* packet, const snet::layers::IPAddress& srcIP,
                                     const snet::layers::TCPHeader& hdr, const snet::layers::LayerInfo* tcpLayer,
                                     layers::PacketStatus status)
    {
        const int8_t idx = determineContextIndex(session, srcIP, hdr.srcPort());
        if (idx < 0)
            return this->passToNext(session, packet, status);

        auto* conn = this->template getContext<TcpConnection>(session, idx);
        if (!conn)
            return this->passToNext(session, packet, layers::PacketStatus::Error_NoContext);

        // Pure SYN — handled by TcpListenerHandler
        if (hdr.isSYN() && !hdr.isACK())
            return this->passToNext(session, packet, status);

        if (conn->closed || conn->state == TcpState::Closed)
            return this->passToNext(session, packet, layers::PacketStatus::Ignore_PacketOfClosedFlow);

        if (!conn->rxRing)
        {
            CSK_LOG_WARNING("TcpReceive: no RX ring for ctx=%d", idx);
            return this->passToNext(session, packet, status);
        }

        TcpSegment seg;
        seg.flags = snet::layers::TcpFlags::fromByte(hdr.flagsByte());
        seg.seq = hdr.seqNum();
        seg.ack = hdr.ackNum();
        seg.window = hdr.window();
        seg.payload = packet->getPayloadData(tcpLayer);
        seg.payloadLen = packet->getPayloadSize(tcpLayer);

        auto result = TcpStateMachine::onRxSegment(*conn, seg);

        if (result.output.type != TcpOutput::Type::None)
        {
            conn->pendingOutput = result.output;
            conn->hasPendingOutput = true;
        }

        if (result.connectionEstablished && acceptor_)
            acceptor_->onAccept(session, *conn);

        if (result.deliverToApp && consumer_)
        {
            RxStreamReader reader{conn->rxRing};
            consumer_->onStreamData(session, idx, reader);
        }

        if (result.closed && consumer_)
            consumer_->onStreamClose(session, idx, 0);

        return this->passToNext(
            session,
            packet,
            result.closed ? layers::PacketStatus::Ignore_PacketOfClosedFlow : layers::PacketStatus::TcpMessageHandled);
    }

    // ============================================================
    // Helpers
    // ============================================================

    /// @brief Determine which direction this packet belongs to.
    ///
    ///   ctx 0: local = server, remote = client
    ///   ctx 1: local = client, remote = server
    ///
    /// @return 0, 1, or -1 (unknown).
    int8_t determineContextIndex(Session* session, const snet::layers::IPAddress& srcIP, uint16_t srcPort) const
    {
        // Check ctx 0: packet from client?
        auto* conn0 = this->template getContext<TcpConnection>(session, kClientSide);
        if (conn0 && conn0->remotePort != 0 && conn0->remoteIP == srcIP && conn0->remotePort == srcPort)
        {
            return kClientSide;
        }

        // Check ctx 1: packet from server?
        auto* conn1 = this->template getContext<TcpConnection>(session, kServerSide);
        if (conn1 && conn1->remotePort != 0 && conn1->remoteIP == srcIP && conn1->remotePort == srcPort)
        {
            return kServerSide;
        }

        return kSideUnknown;
    }

    bool extractPacketInfo(layers::Packet* packet, snet::layers::IPAddress& srcIP, snet::layers::IPAddress& dstIP,
                           snet::layers::TCPHeader& hdr, const snet::layers::LayerInfo*& tcpLayer)
    {
        auto ipHeader = packet->getHeader<snet::layers::IPv4Header>(snet::layers::IPv4);
        if (!ipHeader.isValid())
            return false;

        srcIP = snet::layers::IPAddress(ipHeader.srcAddr());
        dstIP = snet::layers::IPAddress(ipHeader.dstAddr());

        tcpLayer = packet->findLayer(snet::layers::TCP);
        if (!tcpLayer)
            return false;

        hdr = packet->getHeader<snet::layers::TCPHeader>(*tcpLayer);
        return true;
    }

private:
    Acceptor* acceptor_{nullptr};
    Consumer* consumer_{nullptr};
    TcpReceiveHandlerConfig config_;
};

} // namespace snet::tcp