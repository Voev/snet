#pragma once

#include <cstdint>

namespace snet::layers
{

enum class PacketVerdict : uint8_t
{
    Pass,
    Drop,
};

enum class PacketReason : uint8_t
{
    Observed,
    Probing,
    Bypass,
    NonProxyPacket,

    Hijacked,
    Blocked,
    Closed,
    Error,

    None,
    InvalidParameters,
    TcpMessageHandled,
    IgnoreWithNoData,
    IgnoreClosedFlow,
    NonIpPacket,
    NonTcpPacket,
    ErrorNoMemory,
    ErrorNoContext,
    ErrorPacketMismatch,
};

class PacketStatus
{
public:
    PacketVerdict verdict{PacketVerdict::Drop};
    PacketReason reason{PacketReason::None};

    constexpr PacketStatus() noexcept = default;

    constexpr PacketStatus(PacketVerdict v, PacketReason r) noexcept
        : verdict(v)
        , reason(r)
    {
    }

    [[nodiscard]] static constexpr PacketStatus pass(PacketReason r = PacketReason::None) noexcept
    {
        return {PacketVerdict::Pass, r};
    }

    [[nodiscard]] static constexpr PacketStatus drop(PacketReason r = PacketReason::None) noexcept
    {
        return {PacketVerdict::Drop, r};
    }

    [[nodiscard]] constexpr bool passes() const noexcept
    {
        return verdict == PacketVerdict::Pass;
    }

    [[nodiscard]] constexpr bool drops() const noexcept
    {
        return verdict == PacketVerdict::Drop;
    }

    friend constexpr bool operator==(const PacketStatus& a, const PacketStatus& b) noexcept
    {
        return a.verdict == b.verdict && a.reason == b.reason;
    }

    friend constexpr bool operator!=(const PacketStatus& a, const PacketStatus& b) noexcept
    {
        return !(a == b);
    }

    static const PacketStatus Ok;
    static const PacketStatus TcpMessageHandled;
    static const PacketStatus Ignore_PacketWithNoData;
    static const PacketStatus Ignore_PacketOfClosedFlow;
    static const PacketStatus NonIpPacket;
    static const PacketStatus NonTcpPacket;
    static const PacketStatus Error_NoMemory;
    static const PacketStatus Error_NoContext;
    static const PacketStatus Error_PacketDoesNotMatchFlow;
};

inline constexpr PacketStatus PacketStatus::Ok = PacketStatus::pass();

inline constexpr PacketStatus PacketStatus::TcpMessageHandled = PacketStatus::pass(PacketReason::TcpMessageHandled);

inline constexpr PacketStatus PacketStatus::Ignore_PacketWithNoData =
    PacketStatus::drop(PacketReason::IgnoreWithNoData);

inline constexpr PacketStatus PacketStatus::Ignore_PacketOfClosedFlow =
    PacketStatus::drop(PacketReason::IgnoreClosedFlow);

inline constexpr PacketStatus PacketStatus::NonIpPacket = PacketStatus::drop(PacketReason::NonIpPacket);

inline constexpr PacketStatus PacketStatus::NonTcpPacket = PacketStatus::drop(PacketReason::NonTcpPacket);

inline constexpr PacketStatus PacketStatus::Error_NoMemory = PacketStatus::drop(PacketReason::ErrorNoMemory);

inline constexpr PacketStatus PacketStatus::Error_NoContext = PacketStatus::drop(PacketReason::ErrorNoContext);

inline constexpr PacketStatus PacketStatus::Error_PacketDoesNotMatchFlow =
    PacketStatus::drop(PacketReason::ErrorPacketMismatch);

[[nodiscard]] constexpr const char* toString(PacketVerdict v) noexcept
{
    switch (v)
    {
    case PacketVerdict::Pass:
        return "Pass";
    case PacketVerdict::Drop:
        return "Drop";
    }
    return "?";
}

[[nodiscard]] constexpr const char* toString(PacketReason r) noexcept
{
    switch (r)
    {
    case PacketReason::InvalidParameters:
        return "InvalidParameters";
    case PacketReason::Observed:
        return "Observed";
    case PacketReason::Probing:
        return "Probing";
    case PacketReason::Bypass:
        return "Bypass";
    case PacketReason::NonProxyPacket:
        return "NonProxyPacket";
    case PacketReason::Hijacked:
        return "Hijacked";
    case PacketReason::Blocked:
        return "Blocked";
    case PacketReason::Closed:
        return "Closed";
    case PacketReason::Error:
        return "Error";
    case PacketReason::None:
        return "None";
    case PacketReason::TcpMessageHandled:
        return "TcpMessageHandled";
    case PacketReason::IgnoreWithNoData:
        return "IgnoreWithNoData";
    case PacketReason::IgnoreClosedFlow:
        return "IgnoreClosedFlow";
    case PacketReason::NonIpPacket:
        return "NonIpPacket";
    case PacketReason::NonTcpPacket:
        return "NonTcpPacket";
    case PacketReason::ErrorNoMemory:
        return "ErrorNoMemory";
    case PacketReason::ErrorNoContext:
        return "ErrorNoContext";
    case PacketReason::ErrorPacketMismatch:
        return "ErrorPacketMismatch";
    }
    return "?";
}

} // namespace snet::layers