#pragma once
#include <random>
#include <casket/log/log.hpp>
#include <snet/tcp/tcp_connection.hpp>

namespace snet::tcp
{

struct TcpSegment
{
    TcpFlags flags;
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
    TcpFlags flags;
    uint32_t seq{0};
    uint32_t ack{0};
    uint16_t window{0};
    const uint8_t* payload{nullptr};
    size_t payloadLen{0};

    static TcpOutput none()
    {
        return {};
    }

    static TcpOutput send(TcpFlags f, uint32_t seq, uint32_t ack, uint16_t win, const uint8_t* data = nullptr,
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

    static TcpOutput reset(uint32_t seq, uint32_t ack)
    {
        TcpOutput o;
        o.type = Type::SendReset;
        o.flags = {.rst = true, .ack = true};
        o.seq = seq;
        o.ack = ack;
        return o;
    }

    static TcpOutput close()
    {
        TcpOutput o;
        o.type = Type::Close;
        return o;
    }
};

/// @brief TCP FSM — pure logic, no packet I/O.
class TcpStateMachine
{
public:
    struct RxResult
    {
        TcpOutput output;
        bool deliverToApp{false};
        bool closed{false};
        bool connectionEstablished{false};
    };

    // ============================================================
    // Application events
    // ============================================================

    static TcpOutput onActiveOpen(TcpConnection& conn, uint32_t iss)
    {
        if (conn.state != TcpState::Closed)
            return TcpOutput::none();
        conn.iss = iss;
        conn.sndUna = iss;
        conn.sndNxt = iss;
        conn.txRing.initAt(iss);
        conn.state = TcpState::SynSent;
        return TcpOutput::send({.syn = true}, iss, 0, conn.rcvWnd);
    }

    static TcpOutput onPassiveOpen(TcpConnection& conn, const layers::IPAddress& localIP, uint16_t localPort,
                                   const layers::IPAddress& remoteIP, uint16_t remotePort, uint32_t clientISN,
                                   uint32_t ourISN)
    {
        if (conn.state != TcpState::Closed)
            return TcpOutput::none();

        conn.localIP = localIP;
        conn.localPort = localPort;
        conn.remoteIP = remoteIP;
        conn.remotePort = remotePort;
        conn.passiveOpen = true;

        conn.irs = clientISN;
        conn.rcvNxt = clientISN + 1;
        conn.rxRing.initAt(conn.rcvNxt);

        conn.iss = ourISN;
        conn.sndUna = ourISN;
        conn.sndNxt = ourISN;
        conn.txRing.initAt(ourISN);

        conn.state = TcpState::SynReceived;
        conn.lastActivity = std::chrono::steady_clock::now();

        CSK_LOG_DEBUG("TCP [%u] CLOSED -> SYN_RECEIVED (client_isn=%u, our_isn=%u)", localPort, clientISN, ourISN);

        return TcpOutput::send({.syn = true, .ack = true}, ourISN, conn.rcvNxt, conn.rcvWnd);
    }

    static TcpOutput onAppSend(TcpConnection& conn, const uint8_t* data, size_t len)
    {
        if (!conn.inEstablished())
            return TcpOutput::none();
        const size_t accepted = conn.txRing.write(data, len);
        if (accepted == 0)
            return TcpOutput::none();
        return buildSendSegment(conn);
    }

    static TcpOutput onAppClose(TcpConnection& conn)
    {
        switch (conn.state)
        {
        case TcpState::Established:
            conn.finSent = true;
            conn.state = TcpState::FinWait1;
            CSK_LOG_DEBUG("TCP [%u] ESTABLISHED -> FIN_WAIT_1", conn.localPort);
            return TcpOutput::send({.fin = true, .ack = true}, conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        case TcpState::CloseWait:
            conn.finSent = true;
            conn.state = TcpState::LastAck;
            CSK_LOG_DEBUG("TCP [%u] CLOSE_WAIT -> LAST_ACK", conn.localPort);
            return TcpOutput::send({.fin = true, .ack = true}, conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        default:
            return TcpOutput::none();
        }
    }

    static TcpOutput onAppAbort(TcpConnection& conn)
    {
        conn.resetSent = true;
        conn.closed = true;
        conn.state = TcpState::Closed;
        return TcpOutput::reset(conn.sndNxt, conn.rcvNxt);
    }

    // ============================================================
    // RX event
    // ============================================================

    static RxResult onRxSegment(TcpConnection& conn, const TcpSegment& seg)
    {
        RxResult result;
        conn.packetsReceived++;
        conn.lastActivity = std::chrono::steady_clock::now();

        if (seg.flags.rst)
        {
            CSK_LOG_DEBUG("TCP [%u] RST in state %s", conn.localPort, std::string(tcpStateName(conn.state)).c_str());
            conn.state = TcpState::Closed;
            conn.closed = true;
            result.closed = true;
            result.output = TcpOutput::close();
            return result;
        }

        switch (conn.state)
        {
        case TcpState::Closed:
            result.output = handleClosed(conn, seg);
            break;
        case TcpState::SynSent:
            result.output = handleSynSent(conn, seg, result);
            break;
        case TcpState::SynReceived:
            result.output = handleSynReceived(conn, seg, result);
            break;
        case TcpState::Established:
            result.output = handleEstablished(conn, seg, result);
            break;
        case TcpState::FinWait1:
            result.output = handleFinWait1(conn, seg, result);
            break;
        case TcpState::FinWait2:
            result.output = handleFinWait2(conn, seg, result);
            break;
        case TcpState::CloseWait:
            result.output = handleCloseWait(conn, seg, result);
            break;
        case TcpState::Closing:
            result.output = handleClosing(conn, seg, result);
            break;
        case TcpState::LastAck:
            result.output = handleLastAck(conn, seg, result);
            break;
        case TcpState::TimeWait:
            result.output = handleTimeWait(conn, seg, result);
            break;
        default:
            result.output = TcpOutput::reset(conn.sndNxt, conn.rcvNxt);
            break;
        }

        if (conn.closed)
            result.closed = true;
        return result;
    }

    // ============================================================
    // Timers
    // ============================================================

    static TcpOutput onRetransmitTimeout(TcpConnection& conn)
    {
        if (!conn.inEstablished() && conn.state != TcpState::SynSent && conn.state != TcpState::SynReceived)
            return TcpOutput::none();

        conn.retransmits++;

        if (conn.state == TcpState::SynSent)
            return TcpOutput::send({.syn = true}, conn.iss, 0, conn.rcvWnd);

        if (conn.state == TcpState::SynReceived)
            return TcpOutput::send({.syn = true, .ack = true}, conn.iss, conn.rcvNxt, conn.rcvWnd);

        auto [data, len] = conn.txRing.peek();
        if (data && len > 0)
        {
            const size_t chunk = std::min<size_t>(len, conn.mss);
            return TcpOutput::send({.ack = true}, conn.sndUna, conn.rcvNxt, conn.rcvWnd, data, chunk);
        }

        if (conn.finSent)
            return TcpOutput::send({.fin = true, .ack = true}, conn.sndNxt, conn.rcvNxt, conn.rcvWnd);

        return TcpOutput::none();
    }

    static TcpOutput onTimeWaitExpired(TcpConnection& conn)
    {
        if (conn.state != TcpState::TimeWait)
            return TcpOutput::none();
        conn.state = TcpState::Closed;
        conn.closed = true;
        return TcpOutput::close();
    }

    // ============================================================
    // Post-send hook
    // ============================================================

    static void onSegmentSent(TcpConnection& conn, const TcpOutput& out)
    {
        if (out.type != TcpOutput::Type::Send)
            return;
        uint32_t adv = static_cast<uint32_t>(out.payloadLen);
        if (out.flags.syn)
            adv++;
        if (out.flags.fin)
            adv++;
        conn.sndNxt += adv;
        conn.packetsSent++;
        conn.bytesSent += out.payloadLen;
        if (out.payloadLen > 0)
            conn.txRing.advance(out.payloadLen);
    }

private:
    // ============================================================
    // State handlers
    // ============================================================

    static TcpOutput handleClosed(TcpConnection&, const TcpSegment& seg)
    {
        if (seg.flags.ack)
            return TcpOutput::reset(seg.ack, 0);
        return TcpOutput::reset(0, seg.seq + static_cast<uint32_t>(seg.payloadLen) + (seg.flags.syn ? 1 : 0));
    }

    static TcpOutput handleSynSent(TcpConnection& conn, const TcpSegment& seg, RxResult& result)
    {
        if (seg.flags.syn && seg.flags.ack)
        {
            if (seg.ack != conn.sndNxt)
                return TcpOutput::reset(seg.ack, 0);

            conn.irs = seg.seq;
            conn.rcvNxt = seg.seq + 1;
            conn.sndUna = seg.ack;
            conn.sndWnd = seg.window;
            conn.state = TcpState::Established;
            conn.rxRing.initAt(conn.rcvNxt);

            CSK_LOG_DEBUG("TCP [%u] SYN_SENT -> ESTABLISHED", conn.localPort);
            result.connectionEstablished = true;

            return TcpOutput::send({.ack = true}, conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        }

        if (seg.flags.syn && !seg.flags.ack)
        {
            conn.irs = seg.seq;
            conn.rcvNxt = seg.seq + 1;
            conn.state = TcpState::SynReceived;
            CSK_LOG_DEBUG("TCP [%u] SYN_SENT -> SYN_RECEIVED", conn.localPort);
            return TcpOutput::send({.syn = true, .ack = true}, conn.iss, conn.rcvNxt, conn.rcvWnd);
        }

        return TcpOutput::none();
    }

    static TcpOutput handleSynReceived(TcpConnection& conn, const TcpSegment& seg, RxResult& result)
    {
        if (seg.flags.ack && seg.ack == conn.sndNxt)
        {
            conn.sndUna = seg.ack;
            conn.sndWnd = seg.window;
            conn.state = TcpState::Established;
            CSK_LOG_DEBUG("TCP [%u] SYN_RECEIVED -> ESTABLISHED", conn.localPort);
            result.connectionEstablished = true;

            if (seg.payloadLen > 0 && seg.seq == conn.rcvNxt)
            {
                conn.rxRing.writeAt(seg.seq, seg.payload, seg.payloadLen);
                conn.rxRing.advanceContiguous();
                conn.rcvNxt += static_cast<uint32_t>(seg.payloadLen);
                conn.bytesReceived += seg.payloadLen;
                result.deliverToApp = true;
            }
            return TcpOutput::none();
        }

        // Retransmitted SYN
        if (seg.flags.syn && !seg.flags.ack && seg.seq == conn.irs)
        {
            CSK_LOG_DEBUG("TCP [%u] SYN_RECEIVED: retransmitted SYN -> resend SYN-ACK", conn.localPort);
            return TcpOutput::send({.syn = true, .ack = true}, conn.iss, conn.rcvNxt, conn.rcvWnd);
        }

        return TcpOutput::reset(conn.sndNxt, conn.rcvNxt);
    }

    static TcpOutput handleEstablished(TcpConnection& conn, const TcpSegment& seg, RxResult& result)
    {
        if (seg.flags.ack)
            processAck(conn, seg.ack, seg.window);

        if (seg.payloadLen > 0)
        {
            const int32_t diff = static_cast<int32_t>(seg.seq - conn.rcvNxt);

            if (diff == 0)
            {
                conn.rxRing.writeAt(seg.seq, seg.payload, seg.payloadLen);
                conn.rxRing.advanceContiguous();
                conn.rcvNxt += static_cast<uint32_t>(seg.payloadLen);
                conn.bytesReceived += seg.payloadLen;
                result.deliverToApp = true;
            }
            else if (diff > 0)
            {
                // Out-of-order — writeAt handles holes
                conn.rxRing.writeAt(seg.seq, seg.payload, seg.payloadLen);
                conn.rxRing.advanceContiguous();
                conn.dupAcks++;
            }
            else
            {
                // Retransmit — trim front
                const size_t skip = static_cast<size_t>(-diff);
                if (skip < seg.payloadLen)
                {
                    conn.rxRing.writeAt(
                        seg.seq + static_cast<uint32_t>(skip), seg.payload + skip, seg.payloadLen - skip);
                    conn.rxRing.advanceContiguous();
                }
            }
        }

        if (seg.flags.fin)
        {
            conn.rcvNxt++;
            conn.finReceived = true;
            conn.state = TcpState::CloseWait;
            CSK_LOG_DEBUG("TCP [%u] ESTABLISHED -> CLOSE_WAIT", conn.localPort);
            return TcpOutput::send({.ack = true}, conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        }

        if (result.deliverToApp)
        {
            // Send ACK for received data
            return TcpOutput::send({.ack = true}, conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        }

        return buildSendSegment(conn);
    }

    static TcpOutput handleFinWait1(TcpConnection& conn, const TcpSegment& seg, RxResult& result)
    {
        if (seg.flags.ack && seg.ack == conn.sndNxt)
        {
            conn.sndUna = seg.ack;
            if (seg.flags.fin)
            {
                conn.rcvNxt++;
                conn.finReceived = true;
                conn.state = TcpState::Closing;
                CSK_LOG_DEBUG("TCP [%u] FIN_WAIT_1 -> CLOSING", conn.localPort);
                return TcpOutput::send({.ack = true}, conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
            }
            conn.state = TcpState::FinWait2;
            CSK_LOG_DEBUG("TCP [%u] FIN_WAIT_1 -> FIN_WAIT_2", conn.localPort);
        }

        if (seg.flags.fin)
        {
            conn.rcvNxt++;
            conn.finReceived = true;
            if (conn.state == TcpState::FinWait1)
            {
                conn.state = TcpState::Closing;
                CSK_LOG_DEBUG("TCP [%u] FIN_WAIT_1 -> CLOSING (simultaneous)", conn.localPort);
            }
            return TcpOutput::send({.ack = true}, conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        }

        if (seg.payloadLen > 0)
        {
            conn.rxRing.writeAt(seg.seq, seg.payload, seg.payloadLen);
            conn.rxRing.advanceContiguous();
            conn.rcvNxt += static_cast<uint32_t>(seg.payloadLen);
            result.deliverToApp = true;
        }
        return TcpOutput::none();
    }

    static TcpOutput handleFinWait2(TcpConnection& conn, const TcpSegment& seg, RxResult& result)
    {
        if (seg.payloadLen > 0)
        {
            conn.rxRing.writeAt(seg.seq, seg.payload, seg.payloadLen);
            conn.rxRing.advanceContiguous();
            conn.rcvNxt += static_cast<uint32_t>(seg.payloadLen);
            result.deliverToApp = true;
        }

        if (seg.flags.fin)
        {
            conn.rcvNxt++;
            conn.finReceived = true;
            conn.state = TcpState::TimeWait;
            conn.timeWaitStart = std::chrono::steady_clock::now();
            CSK_LOG_DEBUG("TCP [%u] FIN_WAIT_2 -> TIME_WAIT", conn.localPort);
            return TcpOutput::send({.ack = true}, conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        }
        return TcpOutput::none();
    }

    static TcpOutput handleCloseWait(TcpConnection& conn, const TcpSegment& seg, RxResult& res)
    {
        (void)conn;
        (void)seg;
        (void)res;
        // Nothing to do — application must call onAppClose()
        return TcpOutput::none();
    }

    static TcpOutput handleClosing(TcpConnection& conn, const TcpSegment& seg, RxResult&)
    {
        if (seg.flags.ack && seg.ack == conn.sndNxt)
        {
            conn.sndUna = seg.ack;
            conn.state = TcpState::TimeWait;
            conn.timeWaitStart = std::chrono::steady_clock::now();
            CSK_LOG_DEBUG("TCP [%u] CLOSING -> TIME_WAIT", conn.localPort);
        }
        return TcpOutput::none();
    }

    static TcpOutput handleLastAck(TcpConnection& conn, const TcpSegment& seg, RxResult&)
    {
        if (seg.flags.ack && seg.ack == conn.sndNxt)
        {
            conn.state = TcpState::Closed;
            conn.closed = true;
            CSK_LOG_DEBUG("TCP [%u] LAST_ACK -> CLOSED", conn.localPort);
            return TcpOutput::close();
        }
        return TcpOutput::none();
    }

    static TcpOutput handleTimeWait(TcpConnection& conn, const TcpSegment& seg, RxResult&)
    {
        if (seg.flags.fin)
        {
            conn.rcvNxt = seg.seq + 1;
            return TcpOutput::send({.ack = true}, conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        }
        return TcpOutput::none();
    }

    static void processAck(TcpConnection& conn, uint32_t ack, uint16_t window)
    {
        if (static_cast<int32_t>(ack - conn.sndUna) < 0)
            return;
        if (static_cast<int32_t>(ack - conn.sndNxt) > 0)
            return;

        const uint32_t ackedBytes = ack - conn.sndUna;
        if (ackedBytes > 0)
        {
            conn.txRing.ack(ackedBytes);
            conn.sndUna = ack;
            conn.cwnd += (conn.cwnd < conn.ssthresh) ? 1 : 1;
        }

        if (window > 0 &&
            (static_cast<int32_t>(conn.sndNxt - conn.sndWl1) > 0 || static_cast<int32_t>(ack - conn.sndWl2) >= 0))
        {
            conn.sndWnd = window;
            conn.sndWl1 = conn.sndNxt;
            conn.sndWl2 = ack;
        }
    }

    static TcpOutput buildSendSegment(TcpConnection& conn)
    {
        if (!conn.txRing.initialized())
            return TcpOutput::none();
        const size_t pending = conn.txRing.pending();
        if (pending == 0)
            return TcpOutput::none();

        const size_t cwndBytes = conn.cwnd * conn.mss;
        const size_t effective = std::min<size_t>({static_cast<size_t>(conn.sndWnd), cwndBytes, conn.mss});
        if (effective == 0)
            return TcpOutput::none();

        auto [data, len] = conn.txRing.peek();
        if (!data || len == 0)
            return TcpOutput::none();

        const size_t chunk = std::min(len, effective);
        return TcpOutput::send({.psh = true, .ack = true}, conn.sndNxt, conn.rcvNxt, conn.rcvWnd, data, chunk);
    }
};

} // namespace snet::tcp