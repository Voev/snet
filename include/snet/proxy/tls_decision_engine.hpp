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
#include "i_probe_connection.hpp"

#include <casket/log/log.hpp>

namespace snet::proxy
{

/// Decision policy: maps SNI and certificate chain to a verdict.
/// Implemented in main as a lambda, registered once.
using InspectionPolicy = std::function<InspectionDecision(std::string_view sni, const CertificateChain& chain)>;

/// Decision engine: cache + probe + deduplication.
///
/// Responsibilities:
///   * On a decision request — check the cache first.
///   * On cache-miss — start a probe (if not already running for this SNI).
///   * While a probe is in flight — new requests for the same SNI wait on it.
///   * On completion — apply policy, store in cache, wake all waiters.
///
/// Saves full RTTs: 99% of requests are resolved by cache hit, the rest
/// are deduplicated per SNI.
class TlsDecisionEngine
{
public:
    /// @param[in] probe  Probe connection used to fetch the certificate chain.
    /// @param[in] cache  Decision cache keyed by SNI.
    /// @param[in] policy Verdict policy applied on probe success.
    TlsDecisionEngine(IProbeConnection& probe, DecisionCache& cache, InspectionPolicy policy)
        : probe_(probe)
        , cache_(cache)
        , policy_(std::move(policy))
    {
    }

    /// Asynchronous decision request. The callback is invoked exactly once.
    ///
    /// Resolves from cache if possible; otherwise starts or joins an
    /// in-flight probe for the given SNI.
    ///
    /// @param[in] sni        Server Name Indication to resolve.
    /// @param[in] serverIP   Upstream server address for the probe.
    /// @param[in] serverPort Upstream server port for the probe.
    /// @param[in] cb         Completion callback receiving the decision.
    void request(std::string sni, snet::layers::IPAddress serverIP, uint16_t serverPort,
                 std::function<void(InspectionDecision)> cb)
    {
        // 1. Cache.
        if (auto cached = cache_.lookup(sni))
        {
            cb(*cached);
            return;
        }

        // 2. Deduplication.
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

        // 3. Start probe.
        std::cout << "Probe server: " << serverIP << ":" << serverPort << "[" << sni << "]" << std::endl;
        probe_.asyncProbe(sni,
                          serverIP,
                          serverPort,
                          [this, inflight](probe::ProbeResult r)
                          {
                              onProbeComplete(inflight, std::move(r));
                          });
    }

    /// @return Number of SNIs with a probe currently in flight.
    size_t pendingCount() const
    {
        std::lock_guard lock(mtx_);
        return inFlight_.size();
    }

private:
    /// State for a single in-flight probe keyed by SNI.
    struct InFlight
    {
        std::string sni;                                              ///< SNI this probe was started for.
        std::vector<std::function<void(InspectionDecision)>> waiters; ///< Callbacks awaiting the verdict.
    };

    /// Finalize a probe: apply policy, store the decision in cache,
    /// remove the in-flight entry, and notify all waiters.
    ///
    /// @param[in] inflight In-flight entry the probe belongs to.
    /// @param[in] result   Probe result (chain on success, error otherwise).
    void onProbeComplete(const std::shared_ptr<InFlight>& inflight, probe::ProbeResult result)
    {
        InspectionDecision decision = InspectionDecision::Bypass;

        if (result.status == probe::ProbeResult::Status::Ok)
        {
            decision = policy_ ? policy_(inflight->sni, result.chain) : InspectionDecision::Bypass;
        }
        else
        {
            CSK_LOG_WARNING("probe for %s failed: %s, defaulting to Bypass", inflight->sni.c_str());
        }

        cache_.store(inflight->sni, decision);

        // Extract waiters under the lock and remove the in-flight entry.
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

    IProbeConnection& probe_; ///< Probe connection (not owned).
    DecisionCache& cache_;    ///< Decision cache (not owned).
    InspectionPolicy policy_; ///< Verdict policy.

    mutable std::mutex mtx_;                                              ///< Guards inFlight_.
    std::unordered_map<std::string, std::shared_ptr<InFlight>> inFlight_; ///< Active probes keyed by SNI.
};

} // namespace snet::proxy