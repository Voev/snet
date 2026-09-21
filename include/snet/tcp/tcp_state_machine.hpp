#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>

#include <snet/tcp/tcp_types.hpp>

#include <casket/log/log.hpp>

namespace snet::tcp
{

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

    static TcpOutput onActiveOpen(TcpConnection& conn, uint32_t iss)
    {
        if (conn.state != TcpState::Closed)
            return TcpOutput::none();

        conn.iss = iss;
        conn.sndUna = iss;
        conn.sndNxt = iss;
        if (conn.txRing) conn.txRing->initAt(iss);
        conn.state = TcpState::SynSent;

        CSK_LOG_DEBUG("TCP [%u] CLOSED -> SYN_SENT (iss=%u)",
                      conn.localPort, iss);

        return TcpOutput::sendSyn(iss, conn.rcvWnd);
    }

    static TcpOutput onPassiveOpen(TcpConnection& conn,
                                   const layers::IPAddress& localIP,
                                   uint16_t localPort,
                                   const layers::IPAddress& remoteIP,
                                   uint16_t remotePort,
                                   uint32_t clientISN,
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
        if (conn.rxRing) conn.rxRing->initAt(conn.rcvNxt);

        conn.iss = ourISN;
        conn.sndUna = ourISN;
        conn.sndNxt = ourISN;
        if (conn.txRing) conn.txRing->initAt(ourISN);

        conn.state = TcpState::SynReceived;
        conn.lastActivity = std::chrono::steady_clock::now();

        CSK_LOG_DEBUG("TCP [%u] CLOSED -> SYN_RECEIVED "
                      "(client_isn=%u, our_isn=%u)",
                      localPort, clientISN, ourISN);

        return TcpOutput::sendSynAck(ourISN, conn.rcvNxt, conn.rcvWnd);
    }

    static TcpOutput onAppSend(TcpConnection& conn,
                               const uint8_t* data, size_t len)
    {
        if (!conn.inEstablished() || !conn.txRing)
            return TcpOutput::none();

        const size_t accepted = conn.txRing->write(data, len);
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
            return TcpOutput::sendFinAck(conn.sndNxt, conn.rcvNxt, conn.rcvWnd);

        case TcpState::CloseWait:
            conn.finSent = true;
            conn.state = TcpState::LastAck;
            CSK_LOG_DEBUG("TCP [%u] CLOSE_WAIT -> LAST_ACK", conn.localPort);
            return TcpOutput::sendFinAck(conn.sndNxt, conn.rcvNxt, conn.rcvWnd);

        default:
            return TcpOutput::none();
        }
    }

    static TcpOutput onAppAbort(TcpConnection& conn)
    {
        conn.resetSent = true;
        conn.closed = true;
        conn.state = TcpState::Closed;
        return TcpOutput::sendRst(conn.sndNxt, conn.rcvNxt);
    }

    static RxResult onRxSegment(TcpConnection& conn, const TcpSegment& seg)
    {
        RxResult result;
        conn.packetsReceived++;
        conn.lastActivity = std::chrono::steady_clock::now();

        // Any RST → abort connection immediately
        if (seg.flags.hasRst())
        {
            CSK_LOG_DEBUG("TCP [%u] RST in state %s",
                          conn.localPort,
                          std::string(tcpStateName(conn.state)).c_str());
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
            result.output = TcpOutput::sendRst(conn.sndNxt, conn.rcvNxt);
            break;
        }

        if (conn.closed)
            result.closed = true;
        return result;
    }

    static TcpOutput onRetransmitTimeout(TcpConnection& conn)
    {
        if (!conn.inEstablished() &&
            conn.state != TcpState::SynSent &&
            conn.state != TcpState::SynReceived)
            return TcpOutput::none();

        conn.retransmits++;

        if (conn.state == TcpState::SynSent)
            return TcpOutput::sendSyn(conn.iss, conn.rcvWnd);

        if (conn.state == TcpState::SynReceived)
            return TcpOutput::sendSynAck(conn.iss, conn.rcvNxt, conn.rcvWnd);

        // Retransmit from sndUna (not from pending position)
        if (conn.txRing)
        {
            auto [data, len] = conn.txRing->peekAt(conn.sndUna);
            if (data && len > 0)
            {
                const size_t chunk = std::min<size_t>(len, conn.mss);
                return TcpOutput::sendData(conn.sndUna, conn.rcvNxt,
                                           conn.rcvWnd, data, chunk);
            }
        }

        if (conn.finSent)
            return TcpOutput::sendFinAck(conn.sndNxt, conn.rcvNxt, conn.rcvWnd);

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

    /// @brief Updates sequence numbers after a segment has been sent.
    ///
    /// Must be called ONLY by the handler that actually transmitted the
    /// segment (i.e. TcpTransmitHandler).
    static void onSegmentSent(TcpConnection& conn, const TcpOutput& out)
    {
        if (out.type != TcpOutput::Type::Send)
            return;

        uint32_t adv = static_cast<uint32_t>(out.payloadLen);
        if (out.flags.hasSyn()) adv++;
        if (out.flags.hasFin()) adv++;

        conn.sndNxt += adv;
        conn.packetsSent++;
        conn.bytesSent += out.payloadLen;

        if (out.payloadLen > 0 && conn.txRing)
            conn.txRing->advance(out.payloadLen);
    }

private:

    static TcpOutput handleClosed(TcpConnection&, const TcpSegment& seg)
    {
        // Any segment in CLOSED → send RST
        if (seg.flags.hasAck())
            return TcpOutput::sendRst(seg.ack, 0);

        const uint32_t ack = seg.seq
            + static_cast<uint32_t>(seg.payloadLen)
            + (seg.flags.hasSyn() ? 1u : 0u);
        return TcpOutput::sendRst(0, ack);
    }

    static TcpOutput handleSynSent(TcpConnection& conn,
                                   const TcpSegment& seg,
                                   RxResult& result)
    {
        // SYN + ACK → ESTABLISHED
        if (seg.flags.isSynAck())
        {
            if (seg.ack != conn.sndNxt)
                return TcpOutput::sendRst(seg.ack, 0);

            conn.irs = seg.seq;
            conn.rcvNxt = seg.seq + 1;
            conn.sndUna = seg.ack;
            conn.sndWnd = seg.window;
            conn.state = TcpState::Established;
            if (conn.rxRing) conn.rxRing->initAt(conn.rcvNxt);

            CSK_LOG_DEBUG("TCP [%u] SYN_SENT -> ESTABLISHED", conn.localPort);
            result.connectionEstablished = true;

            return TcpOutput::sendAck(conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        }

        // SYN only (simultaneous open) → SYN_RECEIVED
        if (seg.flags.isSynOnly())
        {
            conn.irs = seg.seq;
            conn.rcvNxt = seg.seq + 1;
            conn.state = TcpState::SynReceived;
            CSK_LOG_DEBUG("TCP [%u] SYN_SENT -> SYN_RECEIVED", conn.localPort);
            return TcpOutput::sendSynAck(conn.iss, conn.rcvNxt, conn.rcvWnd);
        }

        return TcpOutput::none();
    }

    static TcpOutput handleSynReceived(TcpConnection& conn,
                                       const TcpSegment& seg,
                                       RxResult& result)
    {
        // ACK of our SYN → ESTABLISHED
        if (seg.flags.hasAck() && seg.ack == conn.sndNxt)
        {
            conn.sndUna = seg.ack;
            conn.sndWnd = seg.window;
            conn.state = TcpState::Established;
            CSK_LOG_DEBUG("TCP [%u] SYN_RECEIVED -> ESTABLISHED", conn.localPort);
            result.connectionEstablished = true;

            // Fast path: ACK may carry data
            if (seg.payloadLen > 0 && seg.seq == conn.rcvNxt && conn.rxRing)
            {
                conn.rxRing->writeAt(seg.seq, seg.payload, seg.payloadLen);
                conn.rxRing->advanceContiguous();
                conn.rcvNxt += static_cast<uint32_t>(seg.payloadLen);
                conn.bytesReceived += seg.payloadLen;
                result.deliverToApp = true;
            }
            return TcpOutput::none();
        }

        // Retransmitted SYN → resend SYN-ACK
        if (seg.flags.isSynOnly() && seg.seq == conn.irs)
        {
            CSK_LOG_DEBUG("TCP [%u] SYN_RECEIVED: retransmitted SYN → "
                          "resend SYN-ACK", conn.localPort);
            return TcpOutput::sendSynAck(conn.iss, conn.rcvNxt, conn.rcvWnd);
        }

        return TcpOutput::sendRst(conn.sndNxt, conn.rcvNxt);
    }

    static TcpOutput handleEstablished(TcpConnection& conn,
                                       const TcpSegment& seg,
                                       RxResult& result)
    {
        if (seg.flags.hasAck())
            processAck(conn, seg.ack, seg.window);

        if (seg.payloadLen > 0 && conn.rxRing)
        {
            const int32_t diff = static_cast<int32_t>(seg.seq - conn.rcvNxt);

            if (diff == 0)
            {
                conn.rxRing->writeAt(seg.seq, seg.payload, seg.payloadLen);
                conn.rxRing->advanceContiguous();
                conn.rcvNxt += static_cast<uint32_t>(seg.payloadLen);
                conn.bytesReceived += seg.payloadLen;
                result.deliverToApp = true;
            }
            else if (diff > 0)
            {
                // Out-of-order: writeAt handles holes via bitmap
                conn.rxRing->writeAt(seg.seq, seg.payload, seg.payloadLen);
                conn.rxRing->advanceContiguous();
                conn.dupAcks++;
            }
            else
            {
                // Retransmit: trim front
                const size_t skip = static_cast<size_t>(-diff);
                if (skip < seg.payloadLen)
                {
                    conn.rxRing->writeAt(
                        seg.seq + static_cast<uint32_t>(skip),
                        seg.payload + skip,
                        seg.payloadLen - skip);
                    conn.rxRing->advanceContiguous();
                }
            }
        }

        if (seg.flags.hasFin())
        {
            conn.rcvNxt++;
            conn.finReceived = true;
            conn.state = TcpState::CloseWait;
            CSK_LOG_DEBUG("TCP [%u] ESTABLISHED -> CLOSE_WAIT", conn.localPort);
            return TcpOutput::sendAck(conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        }

        if (result.deliverToApp)
            return TcpOutput::sendAck(conn.sndNxt, conn.rcvNxt, conn.rcvWnd);

        return buildSendSegment(conn);
    }

    static TcpOutput handleFinWait1(TcpConnection& conn,
                                    const TcpSegment& seg,
                                    RxResult& result)
    {
        // ACK of our FIN
        if (seg.flags.hasAck() && seg.ack == conn.sndNxt)
        {
            conn.sndUna = seg.ack;

            if (seg.flags.hasFin())
            {
                conn.rcvNxt++;
                conn.finReceived = true;
                conn.state = TcpState::Closing;
                CSK_LOG_DEBUG("TCP [%u] FIN_WAIT_1 -> CLOSING", conn.localPort);
                return TcpOutput::sendAck(conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
            }

            conn.state = TcpState::FinWait2;
            CSK_LOG_DEBUG("TCP [%u] FIN_WAIT_1 -> FIN_WAIT_2", conn.localPort);
        }

        // FIN from peer (simultaneous close)
        if (seg.flags.hasFin())
        {
            conn.rcvNxt++;
            conn.finReceived = true;
            if (conn.state == TcpState::FinWait1)
            {
                conn.state = TcpState::Closing;
                CSK_LOG_DEBUG("TCP [%u] FIN_WAIT_1 -> CLOSING (simultaneous)",
                              conn.localPort);
            }
            return TcpOutput::sendAck(conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        }

        // Data (rare in FIN_WAIT_1)
        if (seg.payloadLen > 0 && conn.rxRing)
        {
            conn.rxRing->writeAt(seg.seq, seg.payload, seg.payloadLen);
            conn.rxRing->advanceContiguous();
            conn.rcvNxt += static_cast<uint32_t>(seg.payloadLen);
            result.deliverToApp = true;
        }
        return TcpOutput::none();
    }

    static TcpOutput handleFinWait2(TcpConnection& conn,
                                    const TcpSegment& seg,
                                    RxResult& result)
    {
        if (seg.payloadLen > 0 && conn.rxRing)
        {
            conn.rxRing->writeAt(seg.seq, seg.payload, seg.payloadLen);
            conn.rxRing->advanceContiguous();
            conn.rcvNxt += static_cast<uint32_t>(seg.payloadLen);
            result.deliverToApp = true;
        }

        if (seg.flags.hasFin())
        {
            conn.rcvNxt++;
            conn.finReceived = true;
            conn.state = TcpState::TimeWait;
            conn.timeWaitStart = std::chrono::steady_clock::now();
            CSK_LOG_DEBUG("TCP [%u] FIN_WAIT_2 -> TIME_WAIT", conn.localPort);
            return TcpOutput::sendAck(conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        }
        return TcpOutput::none();
    }

    static TcpOutput handleCloseWait(TcpConnection&, const TcpSegment&, RxResult&)
    {
        // Nothing to do — application must call onAppClose()
        return TcpOutput::none();
    }

    static TcpOutput handleClosing(TcpConnection& conn,
                                   const TcpSegment& seg,
                                   RxResult&)
    {
        if (seg.flags.hasAck() && seg.ack == conn.sndNxt)
        {
            conn.sndUna = seg.ack;
            conn.state = TcpState::TimeWait;
            conn.timeWaitStart = std::chrono::steady_clock::now();
            CSK_LOG_DEBUG("TCP [%u] CLOSING -> TIME_WAIT", conn.localPort);
        }
        return TcpOutput::none();
    }

    static TcpOutput handleLastAck(TcpConnection& conn,
                                   const TcpSegment& seg,
                                   RxResult&)
    {
        if (seg.flags.hasAck() && seg.ack == conn.sndNxt)
        {
            conn.state = TcpState::Closed;
            conn.closed = true;
            CSK_LOG_DEBUG("TCP [%u] LAST_ACK -> CLOSED", conn.localPort);
            return TcpOutput::close();
        }
        return TcpOutput::none();
    }

    static TcpOutput handleTimeWait(TcpConnection& conn,
                                    const TcpSegment& seg,
                                    RxResult&)
    {
        // Retransmitted FIN → re-ACK
        if (seg.flags.hasFin())
        {
            conn.rcvNxt = seg.seq + 1;
            return TcpOutput::sendAck(conn.sndNxt, conn.rcvNxt, conn.rcvWnd);
        }
        return TcpOutput::none();
    }

    static void processAck(TcpConnection& conn, uint32_t ack, uint16_t window)
    {
        // Ignore ACKs outside [sndUna, sndNxt]
        if (static_cast<int32_t>(ack - conn.sndUna) < 0) return;
        if (static_cast<int32_t>(ack - conn.sndNxt) > 0) return;

        const uint32_t ackedBytes = ack - conn.sndUna;
        if (ackedBytes > 0)
        {
            if (conn.txRing) conn.txRing->ack(ackedBytes);
            conn.sndUna = ack;

            // Slow start / congestion avoidance
            if (conn.cwnd < conn.ssthresh)
                conn.cwnd += 1;         // slow start
            else
                conn.cwnd += 1;         // simplified; real impl uses 1/cwnd
        }

        // Window update (RFC 793 §3.9)
        if (window > 0 &&
            (static_cast<int32_t>(conn.sndNxt - conn.sndWl1) > 0 ||
             static_cast<int32_t>(ack - conn.sndWl2) >= 0))
        {
            conn.sndWnd = window;
            conn.sndWl1 = conn.sndNxt;
            conn.sndWl2 = ack;
        }
    }

    static TcpOutput buildSendSegment(TcpConnection& conn)
    {
        if (!conn.txRing || !conn.txRing->initialized())
            return TcpOutput::none();

        if (conn.txRing->pending() == 0)
            return TcpOutput::none();

        const size_t cwndBytes = static_cast<size_t>(conn.cwnd) * conn.mss;
        const size_t effective = std::min<size_t>(
            {static_cast<size_t>(conn.sndWnd), cwndBytes, conn.mss});
        if (effective == 0)
            return TcpOutput::none();

        auto [data, len] = conn.txRing->peek();
        if (!data || len == 0)
            return TcpOutput::none();

        const size_t chunk = std::min(len, effective);
        return TcpOutput::sendData(conn.sndNxt, conn.rcvNxt,
                                   conn.rcvWnd, data, chunk);
    }
};

} // namespace snet::tcp