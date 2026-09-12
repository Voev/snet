#pragma once
#include <cstdint>
#include <chrono>

#include <snet/layers/l3/ip_address.hpp>
#include <snet/tcp/tcp_state.hpp>
#include <snet/utils/rx_ring_buffer.hpp>
#include <snet/utils/tx_ring_buffer.hpp>

namespace snet::tcp
{

/// @brief Per-connection TCP state (both sides).
///
/// This is the analogue of TLDK's `struct tcp_stream` and Linux's
/// `struct tcp_sock`. One instance per TCP connection.
struct TcpConnection
{
    // ============================================================
    // Endpoints
    // ============================================================
    layers::IPAddress localIP;
    layers::IPAddress remoteIP;
    uint16_t localPort{0};
    uint16_t remotePort{0};

    // ============================================================
    // State
    // ============================================================
    TcpState state{TcpState::Closed};
    bool passiveOpen{false}; // true if LISTEN accepted the connection

    // ============================================================
    // Send side (our outgoing data)
    // ============================================================
    uint32_t sndUna{0}; // oldest unacknowledged seq
    uint32_t sndNxt{0}; // next seq to send
    uint32_t sndWnd{0}; // peer's advertised window
    uint32_t sndWl1{0}; // seq of last window update
    uint32_t sndWl2{0}; // ack of last window update
    uint32_t iss{0};    // initial send seq
    uint16_t mss{1460};
    uint32_t cwnd{1}; // congestion window (in MSS)
    uint32_t ssthresh{65535};

    TxRingBuffer txRing;

    // ============================================================
    // Receive side (incoming data)
    // ============================================================
    uint32_t rcvNxt{0}; // next seq expected
    uint32_t rcvWnd{65535};
    uint32_t irs{0}; // initial receive seq (peer's ISS)

    RxRingBuffer rxRing;

    // ============================================================
    // Timers
    // ============================================================
    std::chrono::steady_clock::time_point lastActivity;
    std::chrono::steady_clock::time_point timeWaitStart;
    uint32_t rto{1000}; // retransmit timeout (ms)
    uint32_t timeWaitMs{30000};

    // ============================================================
    // Flags
    // ============================================================
    bool finSent{false};
    bool finReceived{false};
    bool resetSent{false};
    bool closed{false};

    // ============================================================
    // Stats
    // ============================================================
    uint64_t packetsReceived{0};
    uint64_t packetsSent{0};
    uint64_t bytesReceived{0};
    uint64_t bytesSent{0};
    uint64_t retransmits{0};
    uint64_t dupAcks{0};

    void reset() noexcept
    {
        state = TcpState::Closed;
        passiveOpen = false;
        sndUna = sndNxt = sndWnd = sndWl1 = sndWl2 = iss = 0;
        rcvNxt = rcvWnd = irs = 0;
        finSent = finReceived = resetSent = closed = false;
        txRing.reset();
        rxRing.reset();
        packetsReceived = packetsSent = 0;
        bytesReceived = bytesSent = retransmits = dupAcks = 0;
    }

    bool inEstablished() const noexcept
    {
        return state == TcpState::Established || state == TcpState::FinWait1 || state == TcpState::FinWait2 ||
               state == TcpState::CloseWait || state == TcpState::Closing || state == TcpState::LastAck;
    }

    bool isTerminal() const noexcept
    {
        return state == TcpState::Closed || state == TcpState::TimeWait;
    }
};

} // namespace snet::tcp