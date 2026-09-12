#pragma once
#include <cstdint>
#include <casket/nonstd/string_view.hpp>

namespace snet::tcp
{

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

/// @brief TCP flags (RFC 793).
struct TcpFlags
{
    bool fin{false};
    bool syn{false};
    bool rst{false};
    bool psh{false};
    bool ack{false};
    bool urg{false};

    static TcpFlags fromByte(uint8_t b) noexcept
    {
        return TcpFlags{
            .fin = (b & 0x01) != 0,
            .syn = (b & 0x02) != 0,
            .rst = (b & 0x04) != 0,
            .psh = (b & 0x08) != 0,
            .ack = (b & 0x10) != 0,
            .urg = (b & 0x20) != 0,
        };
    }
};

/// @brief Direction of a TCP event.
enum class TcpDirection : uint8_t
{
    Rx, // packet from network
    Tx, // application sending
};

/// @brief Result of processing an event.
enum class TcpAction : uint8_t
{
    None,            // nothing to do
    SendSegment,     // emit a TCP segment (ACK, SYN, FIN, data)
    SendReset,       // emit RST and close
    DeliverData,     // data ready for application (after RX)
    CloseConnection, // tear down the session
};

} // namespace snet::tcp