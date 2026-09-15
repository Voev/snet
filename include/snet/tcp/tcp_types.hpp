#pragma once
#include <cstdint>
#include <chrono>

#include <snet/layers/l3/ip_address.hpp>
#include <snet/layers/l4/tcp_flags.hpp>

#include <snet/utils/rx_ring_buffer.hpp>
#include <snet/utils/tx_ring_buffer.hpp>

#include <casket/types/fixed_object_pool.hpp>
#include <casket/nonstd/string_view.hpp>

namespace snet::tcp
{

using RxRingPool = casket::FixedObjectPool<RxRingBuffer>;
using TxRingPool = casket::FixedObjectPool<TxRingBuffer>;

/// @brief TCP connection states (RFC 793).
enum class TcpState : uint8_t
{
    Closed = 0,
    Listen = 1,
    SynSent = 2,
    SynReceived = 3,
    Established = 4,
    FinWait1 = 5,
    FinWait2 = 6,
    CloseWait = 7,
    Closing = 8,
    LastAck = 9,
    TimeWait = 10,
};

constexpr nonstd::string_view tcpStateName(TcpState s) noexcept
{
    switch (s)
    {
    case TcpState::Closed:
        return "CLOSED";
    case TcpState::Listen:
        return "LISTEN";
    case TcpState::SynSent:
        return "SYN_SENT";
    case TcpState::SynReceived:
        return "SYN_RECEIVED";
    case TcpState::Established:
        return "ESTABLISHED";
    case TcpState::FinWait1:
        return "FIN_WAIT_1";
    case TcpState::FinWait2:
        return "FIN_WAIT_2";
    case TcpState::CloseWait:
        return "CLOSE_WAIT";
    case TcpState::Closing:
        return "CLOSING";
    case TcpState::LastAck:
        return "LAST_ACK";
    case TcpState::TimeWait:
        return "TIME_WAIT";
    }
    return "UNKNOWN";
}

struct TcpSegment
{
    layers::TcpFlags flags;
    uint32_t seq{0};
    uint32_t ack{0};
    uint16_t window{0};
    const uint8_t* payload{nullptr};
    size_t payloadLen{0};
};

struct TcpOutput
{
    enum class Type : uint8_t
    {
        None,
        Send,
        SendReset,
        Close
    };

    Type type{Type::None};
    layers::TcpFlags flags;
    uint32_t seq{0};
    uint32_t ack{0};
    uint16_t window{0};
    const uint8_t* payload{nullptr};
    size_t payloadLen{0};

    static TcpOutput send(layers::TcpFlags f, uint32_t seq, uint32_t ack, uint16_t win, const uint8_t* data = nullptr,
                          size_t len = 0)
    {
        TcpOutput o;
        o.type = Type::Send;
        o.flags = f;
        o.seq = seq;
        o.ack = ack;
        o.window = win;
        o.payload = data;
        o.payloadLen = len;
        return o;
    }

    static TcpOutput none() { return {}; }

    static TcpOutput close()
    {
        TcpOutput o;
        o.type = Type::Close;
        return o;
    }

    static TcpOutput sendSyn(uint32_t seq, uint16_t win)
    {
        return send(layers::TcpFlags::fromByte(layers::TcpFlags::SYN), seq, 0, win);
    }

    static TcpOutput sendSynAck(uint32_t seq, uint32_t ack, uint16_t win)
    {
        return send(layers::TcpFlags::fromByte(layers::TcpFlags::SYN | layers::TcpFlags::ACK),
                    seq, ack, win);
    }

    static TcpOutput sendAck(uint32_t seq, uint32_t ack, uint16_t win)
    {
        return send(layers::TcpFlags::fromByte(layers::TcpFlags::ACK), seq, ack, win);
    }

    static TcpOutput sendFinAck(uint32_t seq, uint32_t ack, uint16_t win)
    {
        return send(layers::TcpFlags::fromByte(layers::TcpFlags::FIN | layers::TcpFlags::ACK),
                    seq, ack, win);
    }

    static TcpOutput sendData(uint32_t seq, uint32_t ack, uint16_t win,
                              const uint8_t* data, size_t len)
    {
        return send(layers::TcpFlags::fromByte(layers::TcpFlags::PSH | layers::TcpFlags::ACK),
                    seq, ack, win, data, len);
    }

    static TcpOutput sendRst(uint32_t seq, uint32_t ack)
    {
        TcpOutput o;
        o.type = Type::SendReset;
        o.flags = layers::TcpFlags::fromByte(layers::TcpFlags::RST | layers::TcpFlags::ACK);
        o.seq = seq;
        o.ack = ack;
        return o;
    }
};

/// @brief Per-connection TCP state (both sides).
///
/// This is the analogue of TLDK's `struct tcp_stream` and Linux's
/// `struct tcp_sock`. One instance per TCP connection.
struct TcpConnection
{
    static constexpr size_t MAX_INSTANCES = 1;

    // ============================================================
    // Endpoints
    // ============================================================
    layers::IPAddress localIP;
    layers::IPAddress remoteIP;
    uint16_t localPort{0};
    uint16_t remotePort{0};

    TcpOutput pendingOutput;
    bool hasPendingOutput{false};

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

    TxRingBuffer* txRing{nullptr};
    bool txRingOwnedByTransmit{false};

    // ============================================================
    // Receive side (incoming data)
    // ============================================================
    uint32_t rcvNxt{0}; // next seq expected
    uint32_t rcvWnd{65535};
    uint32_t irs{0}; // initial receive seq (peer's ISS)

    RxRingBuffer* rxRing{nullptr};
    bool rxRingOwnedByReceive{false};

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
        if (txRing)
            txRing->reset();
        if (rxRing)
            rxRing->reset();
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