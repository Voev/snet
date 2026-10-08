#pragma once

#include <cstdint>

namespace snet::layers
{

/// Что делать драйверу с оригинальным пакетом.
enum class PacketVerdict : uint8_t
{
    Pass,
    Drop,
};

/// Почему pipeline принял такое решение.
enum class PacketReason : uint8_t
{
    
    // ── Pass ──
    Observed,
    Probing,
    Bypass,
    NonProxyPacket,

    // ── Drop ──
    Hijacked,
    Blocked,
    Closed,
    Error,

    // ── Служебные (не сводятся к Pass/Drop) ──
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

/// Результат обработки пакета: вердикт и причина.
///
/// Хранит пару (verdict, reason) в одном значении. Доступ к каждой
/// оси — через `verdict` и `reason`.
///
/// Создаётся через фабрики:
///   * PacketStatus::pass(PacketReason::Observed)
///   * PacketStatus::drop(PacketReason::Hijacked)
///   * PacketStatus::pass()   — Pass без указания причины
///   * PacketStatus::drop()   — Drop без указания причины
class PacketStatus
{
public:
    // ─────────────────────────────────────────────────────────────
    // Данные
    // ─────────────────────────────────────────────────────────────

    PacketVerdict verdict{PacketVerdict::Drop};
    PacketReason reason{PacketReason::None};

    // ─────────────────────────────────────────────────────────────
    // Конструирование
    // ─────────────────────────────────────────────────────────────

    constexpr PacketStatus() noexcept = default;

    constexpr PacketStatus(PacketVerdict v, PacketReason r) noexcept
        : verdict(v)
        , reason(r)
    {
    }

    // ─────────────────────────────────────────────────────────────
    // Фабрики
    // ─────────────────────────────────────────────────────────────

    [[nodiscard]] static constexpr PacketStatus pass(PacketReason r = PacketReason::None) noexcept
    {
        return {PacketVerdict::Pass, r};
    }

    [[nodiscard]] static constexpr PacketStatus drop(PacketReason r = PacketReason::None) noexcept
    {
        return {PacketVerdict::Drop, r};
    }

    // ─────────────────────────────────────────────────────────────
    // Удобные запросы
    // ─────────────────────────────────────────────────────────────

    [[nodiscard]] constexpr bool passes() const noexcept
    {
        return verdict == PacketVerdict::Pass;
    }

    [[nodiscard]] constexpr bool drops() const noexcept
    {
        return verdict == PacketVerdict::Drop;
    }

    // ─────────────────────────────────────────────────────────────
    // Сравнение
    // ─────────────────────────────────────────────────────────────

    friend constexpr bool operator==(const PacketStatus& a, const PacketStatus& b) noexcept
    {
        return a.verdict == b.verdict && a.reason == b.reason;
    }

    friend constexpr bool operator!=(const PacketStatus& a, const PacketStatus& b) noexcept
    {
        return !(a == b);
    }

    // ─────────────────────────────────────────────────────────────
    // Именованные значения (совместимость с существующим кодом)
    //
    // Позволяют писать:
    //   return PacketStatus::TcpMessageHandled;
    //   if (st == PacketStatus::Error_NoContext) { ... }
    //
    // Каждое — обёртка над pass()/drop() с соответствующей причиной.
    // ─────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────
// Определения static-членов.
//
// C++17: constexpr — одно определение на всю программу, .cpp не нужен.
// ─────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────
// Строковые имена для логов.
// ─────────────────────────────────────────────────────────────────

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