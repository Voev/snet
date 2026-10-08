#pragma once

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "decision_cache.hpp"
#include "proxy_types.hpp"
#include "tls_probe_connection.hpp"

#include <casket/log/log.hpp>

namespace snet::proxy
{

/// Решатель: по SNI и цепочке сертификатов возвращает вердикт.
/// Реализуется в main как лямбда, регистрируется один раз.
using InspectionPolicy = std::function<InspectionDecision(std::string_view sni, const CertificateChain& chain)>;

/// Движок решений: кэш + probe + дедупликация.
///
/// Задача:
///   * На запрос решения — сначала проверить кэш.
///   * При cache-miss — запустить probe (если ещё не запущен для этого SNI).
///   * Пока probe в полёте — новые запросы для того же SNI ждут тот же probe.
///   * По завершении — применить policy, записать в кэш, разбудить всех.
///
/// Экономит круглые RTT: 99% запросов решаются hit'ом кэша, остальные
/// — дедуплицируются на уровне SNI.
class TlsDecisionEngine
{
public:
    TlsDecisionEngine(TlsProbeConnection& probe, DecisionCache& cache, InspectionPolicy policy)
        : probe_(probe)
        , cache_(cache)
        , policy_(std::move(policy))
    {
    }

    /// Асинхронный запрос решения. Callback вызовется один раз.
    void request(std::string sni, snet::layers::IPAddress serverIP, uint16_t serverPort,
                 std::function<void(InspectionDecision)> cb)
    {
        // 1. Кэш.
        if (auto cached = cache_.lookup(sni))
        {
            cb(*cached);
            return;
        }

        // 2. Дедупликация.
        std::shared_ptr<InFlight> inflight;
        {
            std::lock_guard lock(mtx_);
            auto it = inFlight_.find(sni);
            if (it != inFlight_.end())
            {
                inflight = it->second;
                inflight->waiters.push_back(std::move(cb));
                return;
            }

            inflight = std::make_shared<InFlight>();
            inflight->sni = sni;
            inflight->waiters.push_back(std::move(cb));
            inFlight_[sni] = inflight;
        }

        // 3. Запуск probe.
        std::cout << "Probe server: " << serverIP << ":" << serverPort << "[" << sni << "]" << std::endl;
        TlsProbeConnection::Config cfg{};
        probe_.asyncProbe(sni,
                          serverIP,
                          serverPort,
                          cfg,
                          [this, inflight](TlsProbeResult r)
                          {
                              onProbeComplete(inflight, std::move(r));
                          });
    }

    size_t pendingCount() const
    {
        std::lock_guard lock(mtx_);
        return inFlight_.size();
    }

private:
    struct InFlight
    {
        std::string sni;
        std::vector<std::function<void(InspectionDecision)>> waiters;
    };

    void onProbeComplete(const std::shared_ptr<InFlight>& inflight, TlsProbeResult result)
    {
        InspectionDecision decision = InspectionDecision::Bypass;

        if (result.status == TlsProbeResult::Status::Ok)
        {
            decision = policy_ ? policy_(inflight->sni, result.chain) : InspectionDecision::Bypass;
        }
        else
        {
            CSK_LOG_WARNING(
                "TlsProbe for %s failed: %s, defaulting to Bypass", inflight->sni.c_str(), result.error.c_str());
        }

        cache_.store(inflight->sni, decision);

        // Извлекаем waiters под блокировкой и удаляем in-flight.
        std::vector<std::function<void(InspectionDecision)>> waiters;
        {
            std::lock_guard lock(mtx_);
            auto it = inFlight_.find(inflight->sni);
            if (it != inFlight_.end())
            {
                waiters = std::move(it->second->waiters);
                inFlight_.erase(it);
            }
        }

        for (auto& cb : waiters)
            cb(decision);
    }

    TlsProbeConnection& probe_;
    DecisionCache& cache_;
    InspectionPolicy policy_;

    mutable std::mutex mtx_;
    std::unordered_map<std::string, std::shared_ptr<InFlight>> inFlight_;
};

} // namespace snet::proxy