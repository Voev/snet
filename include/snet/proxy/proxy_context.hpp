#pragma once

#include <cstdint>

#include "proxy_pair.hpp"

namespace snet::proxy
{

/// Состояние одной из двух сессий пары.
///
/// Всё TCP-состояние живёт в TcpConnection сессии. Здесь только
/// прокси-специфичные поля.
struct ProxyContext
{
    static constexpr size_t MAX_INSTANCES = 1;

    ProxyPairPtr pair;

    bool isDownstream{false};
    bool isUpstream{false};

    uint32_t downstreamKey{0};
    uint32_t upstreamKey{0};

    snet::layers::IPAddress clientIP{};
    uint16_t                clientPort{0};
    snet::layers::IPAddress serverIP{};
    uint16_t                serverPort{0};

    // ─────────────────────────────────────────────────────────────
    // Делегаты к pair->phase.
    //
    // Возвращают разумные значения, даже когда pair ещё не создан:
    //   * до onAccept — Observing (мы видим пакеты, но пары ещё нет);
    //   * после закрытия — Closed.
    // Это позволяет TcpReceiveHandler'у работать с контекстом до
    // того, как акцептор установит связь между сессиями.
    // ─────────────────────────────────────────────────────────────

    /// Пара в фазе наблюдения: TCP установлен, но ClientHello ещё
    /// не обработан, решение не принято.
    [[nodiscard]] bool isObserving() const noexcept
    {
        if (!pair)
            return true;   // пары ещё нет — считаем, что наблюдаем
        return pair->phase == PairPhase::Waiting
            || pair->phase == PairPhase::Probing;
    }

    /// Пара перехвачена: TLS терминируется, либо решение уже принято.
    [[nodiscard]] bool isAttached() const noexcept
    {
        if (!pair)
            return false;
        return pair->phase == PairPhase::Splice
            || pair->phase == PairPhase::Mitm;
    }

    /// Решение — bypass (raw splice).
    [[nodiscard]] bool isSpliced() const noexcept
    {
        return pair && pair->phase == PairPhase::Splice;
    }

    /// Решение — MITM (TLS-терминация).
    [[nodiscard]] bool isMitm() const noexcept
    {
        return pair && pair->phase == PairPhase::Mitm;
    }

    /// Пара закрыта.
    [[nodiscard]] bool isClosed() const noexcept
    {
        return pair && pair->phase == PairPhase::Closed;
    }
};

} // namespace snet::proxy