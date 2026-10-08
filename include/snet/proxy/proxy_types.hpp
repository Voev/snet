#pragma once

#include <string_view>
#include <vector>

#include <snet/crypto/cert.hpp>
#include <snet/layers/packet_status.hpp>

namespace snet::proxy
{

/// Что делать с потоком после получения вердикта.
enum class InspectionDecision
{
    Bypass, ///< Пропустить как есть (raw splice), TLS end-to-end.
    Mitm,   ///< Терминировать TLS с обеих сторон, анализировать.
    Block,  ///< Разорвать соединение.
};

/// Фаза жизненного цикла пары сессий.
enum class PairPhase
{
    Waiting, ///< Клиент установил TCP, ждём ClientHello.
    Probing, ///< ClientHello получен, probe в полёте.
    Splice,  ///< Решение Bypass, байты перекладываются как есть.
    Mitm,    ///< Решение Mitm, TLS-терминация активна.
    Closed,  ///< Пара закрыта.
};

/// Цепочка сертификатов, leaf первым.
using CertificateChain = std::vector<snet::crypto::X509CertPtr>;

/// Соответствие фазы пары и вердикта драйверу.
///
///   Waiting  — TCP установлен, ClientHello ещё не разобран.
///              Оригинал должен дойти до сервера: Pass/Observed.
///
///   Probing  — Идёт probe. Оригинал всё ещё уходит наружу: Pass/Probing.
///
///   Splice   — Решение bypass. Consumer перекладывает байты в txRing.
///              Оригинал НЕ должен уходить, иначе двойная отправка:
///              Drop/Bypass.
///
///   Mitm     — TLS-терминация. Оригинал не нужен: Drop/Hijacked.
///
///   Closed   — Соединение закрыто: Drop/Closed.
[[nodiscard]] constexpr snet::layers::PacketStatus verdictFromPhase(PairPhase phase) noexcept
{
    using snet::layers::PacketStatus;
    using snet::layers::PacketReason;

    switch (phase)
    {
    case PairPhase::Waiting:
    {
        return PacketStatus::pass(PacketReason::Observed);
    }
    case PairPhase::Probing:
    {
        // During probe the packet must NOT be re-injected by the driver:
        // the consumer already holds the bytes in pair.bufferedClientHello
        // and will re-emit them via pushToUpstream once a decision is made.
        // Emitting via bridge would cause a double-send to the server.
        return PacketStatus::drop(PacketReason::Probing);
    }
    case PairPhase::Splice:
        return PacketStatus::drop(PacketReason::Bypass);
    case PairPhase::Mitm:
        return PacketStatus::drop(PacketReason::Hijacked);
    case PairPhase::Closed:
        return PacketStatus::drop(PacketReason::Closed);
    }
    return PacketStatus::drop(PacketReason::Error);
}

} // namespace snet::proxy