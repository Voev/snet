#pragma once
#include <snet/session/session_handler.hpp>

#include <snet/tcp/tcp_state_machine.hpp>
#include <snet/tcp/tcp_stream.hpp>

#include <casket/types/fixed_object_pool.hpp>
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
};

/// @brief RX-side handler — feeds incoming TCP segments to the FSM.
///
/// Owns an RxRingPool; acquires/releases rings per session.
///
/// Responsibilities:
///   - Own RxRingPool.
///   - createContext: acquire RX ring, install into TcpConnection.
///   - destroyContext: return RX ring to pool.
///   - Parse incoming TCP header (zero-copy).
///   - Build TcpSegment view.
///   - Call TcpStateMachine::onRxSegment (transitions + reassembly).
///   - Store FSM output in TcpConnection::pendingOutput for TX handler.
///   - Notify IStreamConsumer on new data.
///   - Notify IConnectionAcceptor on connection established.
///
template <typename SessionManagerType>
class TcpReceiveHandler : public session::ISessionHandler<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;
    using TcpConnection = snet::tcp::TcpConnection;
    using Acceptor = IConnectionAcceptor<SessionManagerType>;
    using Consumer = IStreamConsumer<SessionManagerType>;

    TcpReceiveHandler(RxRingPool* rxPool, Acceptor* acceptor, Consumer* consumer, TcpReceiveHandlerConfig config = {})
        : rxPool_(rxPool)
        , acceptor_(acceptor)
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

    /// @brief Acquires an RX ring from the pool and installs it into
    ///        the session's TcpConnection.
    bool createContext(Session* session) override
    {
        if (!session)
            return false;

        auto* conn = this->template getContext<TcpConnection>(session);
        if (!conn)
        {
            CSK_LOG_ERROR("TcpReceive: no TcpConnection "
                          "(listener must run first)");
            return false;
        }

        if (conn->rxRing != nullptr)
            return true;

        if (!rxPool_)
        {
            CSK_LOG_ERROR("TcpReceive: no RX pool configured");
            return false;
        }

        RxRingBuffer* ring = rxPool_->acquire();
        if (!ring)
        {
            CSK_LOG_WARNING("TcpReceive: RX pool exhausted (capacity=%zu)", rxPool_->capacity());
            return false;
        }

        conn->rxRing = ring;
        conn->rxRingOwnedByReceive = true;

        CSK_LOG_DEBUG("TcpReceive: RX ring acquired for session");
        return true;
    }

    /// @brief Returns the RX ring to the pool.
    bool destroyContext(Session* session) override
    {
        if (!session)
            return false;

        auto* conn = this->template getContext<TcpConnection>(session);
        if (!conn)
            return true;

        if (conn->rxRing && conn->rxRingOwnedByReceive && rxPool_)
        {
            rxPool_->release(conn->rxRing);
            conn->rxRing = nullptr;
            conn->rxRingOwnedByReceive = false;

            CSK_LOG_DEBUG("TcpReceive: RX ring returned to pool");
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

        snet::layers::IPAddress srcIP, dstIP;
        snet::layers::TCPHeader hdr;
        const snet::layers::LayerInfo* tcpLayer = nullptr;

        if (!extractPacketInfo(packet, srcIP, dstIP, hdr, tcpLayer))
            return this->passToNext(session, packet, layers::PacketStatus::NonTcpPacket);

        // Pure SYN — already handled by listener. Pass through.
        if (hdr.isSYN() && !hdr.isACK())
            return this->passToNext(session, packet, status);

        // Closed connection — pass through.
        if (conn->closed || conn->state == TcpState::Closed)
            return this->passToNext(session, packet, layers::PacketStatus::Ignore_PacketOfClosedFlow);

        if (!conn->rxRing)
        {
            CSK_LOG_WARNING("TcpReceive: no RX ring for session");
            return this->passToNext(session, packet, status);
        }

        // Zero-copy segment view
        TcpSegment seg;
        seg.flags = layers::TcpFlags::fromByte(hdr.flagsByte());
        seg.seq = hdr.seqNum();
        seg.ack = hdr.ackNum();
        seg.window = hdr.window();
        seg.payload = packet->getPayloadData(tcpLayer);
        seg.payloadLen = packet->getPayloadSize(tcpLayer);

        // Feed FSM
        auto result = TcpStateMachine::onRxSegment(*conn, seg);

        // Store FSM output for TX handler
        if (result.output.type != TcpOutput::Type::None)
        {
            conn->pendingOutput = result.output;
            conn->hasPendingOutput = true;
        }

        // Notify acceptor
        if (result.connectionEstablished && acceptor_)
        {
            acceptor_->onAccept(session, *conn);
        }

        // Notify consumer on new data
        if (result.deliverToApp && consumer_)
        {
            const int8_t side = determineSide(conn, srcIP, hdr.srcPort());
            if (side >= 0)
            {
                RxStreamReader reader{conn->rxRing};
                consumer_->onStreamData(session, side, reader);
            }
        }

        // Notify on close
        if (result.closed)
        {
            if (consumer_)
            {
                const int8_t side = determineSide(conn, srcIP, hdr.srcPort());
                if (side >= 0)
                {
                    consumer_->onStreamClose(session, side, 0);
                }
            }
            return this->passToNext(session, packet, layers::PacketStatus::Ignore_PacketOfClosedFlow);
        }

        return this->passToNext(session, packet, layers::PacketStatus::TcpMessageHandled);
    }

private:
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

    /// 0 = remote-local, 1 = local-remote, -1 = unknown
    int8_t determineSide(const TcpConnection* conn, const snet::layers::IPAddress& srcIP, uint16_t srcPort) const
    {
        if (conn->remoteIP == srcIP && conn->remotePort == srcPort)
            return 0;
        if (conn->localIP == srcIP && conn->localPort == srcPort)
            return 1;
        return -1;
    }

private:
    RxRingPool* rxPool_{nullptr};
    Acceptor* acceptor_{nullptr};
    Consumer* consumer_{nullptr};
    TcpReceiveHandlerConfig config_;
};

} // namespace snet::tcp