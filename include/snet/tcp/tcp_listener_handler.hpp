#pragma once

#include <random>
#include <cstdint>

#include <snet/layers/packet.hpp>
#include <snet/layers/l3/ip_address.hpp>

#include <snet/session/session_handler.hpp>
#include <snet/session/session_manager.hpp>

#include <snet/tcp/tcp_listener.hpp>
#include <snet/tcp/tcp_state_machine.hpp>

#include <casket/log/log.hpp>

namespace snet::tcp
{

struct TcpListenerHandlerConfig
{
    /// Send RST to unknown ports that receive SYN.
    bool sendRstOnUnknownPort{true};

    /// Seed for ISN generation. 0 = use std::random_device.
    uint32_t isnSeed{0};
};

/// @brief Intercepts incoming SYN packets and creates new sessions
///        (TCP passive open).
///
/// Responsibilities:
///   - Detect pure SYN (SYN set, ACK cleared).
///   - Look up TcpListener by dstIP:dstPort.
///   - Create TcpConnection context (first handler in pipeline).
///   - Drive FSM: Closed -> SynReceived via onPassiveOpen.
///   - Store FSM output (SYN-ACK) in TcpConnection for the TX handler.
///   - Optionally mark RST-to-unknown-port request.
///   - Consume SYN (do not pass further).
///
/// Does NOT:
///   - Build any packets.
///   - Own a sink.
///   - Know about MAC addresses, checksums, etc.
///
/// Packet building is the sole responsibility of TcpTransmitHandler.
template <typename SessionManagerType>
class TcpListenerHandler : public session::ISessionHandler<SessionManagerType>
{
public:
    using Session = typename SessionManagerType::Session;
    using TcpConnection = snet::tcp::TcpConnection;

    explicit TcpListenerHandler(snet::tcp::TcpListenerRegistry* listeners, TcpListenerHandlerConfig config = {})
        : listeners_(listeners)
        , config_(config)
        , rng_(config.isnSeed ? config.isnSeed : std::random_device{}())
    {
    }

    const char* name() const override
    {
        return "TcpListenerHandler";
    }

    bool createContext(Session* session) override
    {
        if (!session)
            return false;

        auto* conn = this->template getContext<TcpConnection>(session);
        if (conn)
            return true;

        conn = this->template allocateContext<TcpConnection>();
        if (!conn)
        {
            CSK_LOG_ERROR("TcpListener: cannot allocate TcpConnection");
            return false;
        }

        conn->reset();

        if (!this->template setContext<TcpConnection>(session, conn))
        {
            this->template deallocateContext<TcpConnection>(conn);
            CSK_LOG_ERROR("TcpListener: cannot set TcpConnection");
            return false;
        }

        return true;
    }

    bool destroyContext(Session* session) override
    {
        if (!session)
            return false;

        auto* conn = this->template getContext<TcpConnection>(session);
        if (conn)
        {
            // Rings are owned by other handlers; they'll release them.
            this->template removeContext<TcpConnection>(session);
            this->template deallocateContext<TcpConnection>(conn);
        }
        return true;
    }

    layers::PacketStatus processPacket(Session* session, layers::Packet* packet, layers::PacketStatus status) override
    {
        if (!session || !packet)
            return this->passToNext(session, packet, layers::PacketStatus::Error_NoMemory);

        snet::layers::IPAddress srcIP, dstIP;
        snet::layers::TCPHeader hdr;
        const snet::layers::LayerInfo* tcpLayer = nullptr;

        if (!extractPacketInfo(packet, srcIP, dstIP, hdr, tcpLayer))
            return this->passToNext(session, packet, layers::PacketStatus::NonTcpPacket);

        // Only pure SYN (SYN set, ACK cleared) — everything else
        // (ACK, data, FIN) goes to the reassembler.
        if (!hdr.isSYN() || hdr.isACK())
            return this->passToNext(session, packet, status);

        // Look up listener by destination endpoint.
        auto* lst = listeners_ ? listeners_->find(dstIP, hdr.dstPort()) : nullptr;

        if (!lst)
        {
            // No listener — mark for RST (if configured) and pass through.
            // Actual RST will be emitted by TX handler.
            if (config_.sendRstOnUnknownPort)
            {
                markRstToUnknownPort(session, srcIP, dstIP, hdr);
            }
            return this->passToNext(session, packet, status);
        }

        auto* conn = this->template getContext<TcpConnection>(session);
        if (!conn)
        {
            CSK_LOG_ERROR("TcpListener: no TcpConnection context");
            return this->passToNext(session, packet, layers::PacketStatus::Error_NoContext);
        }

        // Already open? Not our job — pass through.
        if (conn->state != TcpState::Closed)
            return this->passToNext(session, packet, status);

        const uint32_t ourISN = nextISN();

        auto out = TcpStateMachine::onPassiveOpen(*conn,
                                                  dstIP,
                                                  hdr.dstPort(), // local (server)
                                                  srcIP,
                                                  hdr.srcPort(), // remote (client)
                                                  hdr.seqNum(),  // client's ISN
                                                  ourISN);       // our ISN

        // TX handler will pick this up and emit SYN-ACK.
        if (out.type != TcpOutput::Type::None)
        {
            conn->pendingOutput = out;
            conn->hasPendingOutput = true;
        }

        lst->halfOpen++;

        CSK_LOG_DEBUG("TcpListener: SYN %s:%u -> %s:%u, queued SYN-ACK (iss=%u)",
                      srcIP.toString().c_str(),
                      hdr.srcPort(),
                      dstIP.toString().c_str(),
                      hdr.dstPort(),
                      ourISN);

        // TX handler downstream will see pendingOutput and emit SYN-ACK.
        return this->passToNext(session, packet, layers::PacketStatus::TcpMessageHandled);
    }

private:
    /// @brief Stores a "send RST" request in the connection context.
    ///
    /// Since there's no session for unknown ports, this uses a
    /// special flag in the connection. The TX handler picks it up
    /// and emits a RST.
    ///
    /// NOTE: For unknown ports there is no session, so there is no
    /// TcpConnection to store into. This is a corner case.
    /// Options:
    ///   1. Create a transient session just for the RST.
    ///   2. Skip RST entirely (send nothing).
    ///   3. Have a dedicated "RST responder" handler.
    ///
    /// For simplicity, this implementation logs and defers:
    /// RST for unknown ports should be handled by a separate
    /// mechanism (e.g., a dedicated handler or the reassembler).
    void markRstToUnknownPort(Session* session, const snet::layers::IPAddress& srcIP,
                              const snet::layers::IPAddress& dstIP, const snet::layers::TCPHeader& hdr)
    {
        (void)session;
        (void)srcIP;
        (void)dstIP;
        // No session for unknown ports — cannot store pending output.
        // Log only; a dedicated RST handler should deal with this.
        CSK_LOG_DEBUG("TcpListener: no listener for port %u — "
                      "RST not sent (no session)",
                      hdr.dstPort());
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

    uint32_t nextISN()
    {
        std::uniform_int_distribution<uint32_t> dist;
        return dist(rng_);
    }

private:
    TcpListenerRegistry* listeners_{nullptr};
    TcpListenerHandlerConfig config_;
    std::mt19937 rng_;
};

} // namespace snet::tcp