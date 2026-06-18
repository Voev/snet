#pragma once
#include <chrono>
#include <memory>
#include <thread>
#include <vector>
#include <atomic>
#include <functional>
#include <iostream>
#include <cassert>

#include <casket/types/ttl_cache.hpp>
#include <casket/lock_free/queue.hpp>

/// @todo move to casket
#include <snet/pki/ttl_cache.hpp>


#include <snet/crypto/cert.hpp>
#include <snet/pki/cert_fingerprint.hpp>


namespace snet::pki
{

using L1CertCache = casket::TtlCache<CertFingerprint, crypto::X509CertPtr>;

using L2CertCache = casket::concurrency::TtlCache<CertFingerprint, crypto::X509CertPtr>;

struct CacheConfig
{
    std::chrono::seconds l1Ttl{3600};     // L1 cache TTL
    std::chrono::seconds l2Ttl{300};      // L2 cache TTL
    std::chrono::seconds staleTtl{86400}; // Stale TTL для fallback
    size_t workerThreads{4};
    size_t batchSize{8};
    std::chrono::milliseconds queueTimeout{100};
    std::chrono::milliseconds popTimeout{10};
};

class WorkerPool
{
public:
    using Clock = std::chrono::steady_clock;
    using EnricherFunc =
        std::function<crypto::X509CertPtr(const CertFingerprint&, const std::string& policy, const std::string& originCert)>;

    struct EnrichmentTask
    {
        CertFingerprint fingerprint;
        std::string policy;
        std::string originCert;
        Clock::time_point enqueueTime;
        uint64_t attempt = 0;

        EnrichmentTask() = default;
        EnrichmentTask(CertFingerprint fp, std::string p, std::string cert)
            : fingerprint(fp)
            , policy(std::move(p))
            , originCert(std::move(cert))
            , enqueueTime(Clock::now())
        {
        }
    };

    WorkerPool(EnricherFunc enricher, L2CertCache* l2, const CacheConfig& cfg = CacheConfig{})
        : enricher(std::move(enricher))
        , l2Cache(l2)
        , config(cfg)
    {
        for (size_t i = 0; i < config.workerThreads; ++i)
        {
            workers.emplace_back([this] { workerLoop(); });
        }
    }

    ~WorkerPool()
    {
        running = false;
        for (auto& worker : workers)
        {
            if (worker.joinable())
                worker.join();
        }
    }

    void enrichAsync(const CertFingerprint key, const std::string& policy, const std::string& cert)
    {
        if (!running)
            return;

        EnrichmentTask task(key, policy, cert);
        requestQueue.push(task);
    }

    uint64_t getProcessedCount() const
    {
        return totalProcessed.load();
    }
    uint64_t getFailedCount() const
    {
        return totalFailed.load();
    }

private:
    void workerLoop()
    {
        std::vector<EnrichmentTask> batch;
        batch.reserve(config.batchSize);

        while (running)
        {
            batch.clear();

            auto startTime = Clock::now();

            while (batch.size() < config.batchSize)
            {
                auto popResult = requestQueue.pop();
                if (popResult.has_value())
                {
                    batch.push_back(std::move(popResult.value()));
                }

                if (Clock::now() - startTime > config.queueTimeout && !batch.empty())
                    break;

                if (batch.empty())
                {
                    std::this_thread::sleep_for(config.popTimeout);
                    continue;
                }
            }

            if (batch.empty())
                continue;

            processBatch(batch);
        }
    }

    void processBatch(std::vector<EnrichmentTask>& batch)
    {
        for (auto& task : batch)
        {
            auto start = Clock::now();

            try
            {
                auto now = Clock::now();
                auto existing = l2Cache->get(task.fingerprint, now);
                if (existing)
                {
                    continue;
                }

                if (auto enrichedValue = enricher(task.fingerprint, task.policy, task.originCert))
                {
                    auto expiry = now + config.l2Ttl;

                    l2Cache->put(task.fingerprint, std::move(enrichedValue), expiry);
                    totalProcessed++;
                }
                else
                {
                    totalFailed++;
                    std::cerr << "Enricher returned null for key: " << task.fingerprint.hash << std::endl;
                }
            }
            catch (const std::exception& e)
            {
                totalFailed++;
                std::cerr << "Enrichment failed for key: " << task.fingerprint.hash << " " << task.attempt
                          << ", error: " << e.what() << std::endl;

                // Retry logic with exponential backoff
                if (task.attempt < 3)
                {
                    task.attempt++;
                    task.enqueueTime = Clock::now();
                    requestQueue.push(task);

                    std::this_thread::sleep_for(std::chrono::milliseconds(100 * (1 << task.attempt)));
                }
            }

            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start);

            if (duration > std::chrono::seconds(5))
            {
                std::cerr << "Slow enrichment for key: " << task.fingerprint.toString() << ", took " << duration.count() << "ms"
                          << std::endl;
            }
        }
    }

private:
    casket::lock_free::Queue<EnrichmentTask> requestQueue;
    std::vector<std::thread> workers;
    std::atomic<bool> running{true};

    EnricherFunc enricher;
    L2CertCache* l2Cache;
    CacheConfig config;

    std::atomic<uint64_t> totalProcessed{0};
    std::atomic<uint64_t> totalFailed{0};
};

class CertCache
{
private:
    using Clock = std::chrono::steady_clock;

    L2CertCache l2Cache;
    WorkerPool workerPool;
    CacheConfig config;

    static inline thread_local std::unique_ptr<L1CertCache> tl_L1Cache;
    static inline thread_local Clock::time_point tl_L2Refresh;
    static inline thread_local bool tl_L1Initialized = false;

    void ensureL1Cache()
    {
        if (!tl_L1Initialized)
        {
            tl_L1Cache = std::make_unique<L1CertCache>(1024);
            tl_L1Initialized = true;
            tl_L2Refresh = Clock::now();
        }
    }

public:
    CertCache(const CacheConfig& cfg = CacheConfig{})
        : l2Cache(256, cfg.l2Ttl)
        , workerPool([this](const CertFingerprint& fp, const std::string& policy, const std::string& cert)
                     { return enrichCertificate(fp, policy, cert); }, &l2Cache, cfg)
        , config(cfg)
    {
    }

    crypto::X509CertPtr get(X509Cert* originCert, const std::string& policy, const std::string& cert)
    {
        if (!originCert)
            return nullptr;

        ensureL1Cache();

        auto key = CertFingerprintGenerator::generate(originCert, EVP_sha1());
        auto now = Clock::now();

        // L1 lookup (очень быстрый)
        if (auto value = tl_L1Cache->get(key, now))
        {
            return crypto::Cert::shallowCopy(*value);
        }

        if (auto val = l2Cache.get(key, now))
        {
            promoteToL1(key, crypto::Cert::shallowCopy(*val), now);
            return crypto::Cert::shallowCopy(*val);
        }

        workerPool.enrichAsync(key, policy, cert);

        return nullptr;
    }

    crypto::X509CertPtr getBlocking(X509Cert* originCert, const std::string& policy, const std::string& cert,
                                    std::chrono::milliseconds timeout)
    {
        auto start = Clock::now();

        while (true)
        {
            if (auto val = get(originCert, policy, cert))
            {
                return val;
            }

            if (Clock::now() - start > timeout)
            {
                std::cerr << "Timeout waiting for certificate enrichment" << std::endl;
                return nullptr;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    struct CacheStats
    {
        size_t l2Size;
        uint64_t workerProcessed;
        uint64_t workerFailed;
    };

    CacheStats getStats() const
    {
        return {.l2Size = l2Cache.size(),
                .workerProcessed = workerPool.getProcessedCount(),
                .workerFailed = workerPool.getFailedCount()};
    }

    static void clearThreadLocalCache()
    {
        if (tl_L1Initialized)
        {
            tl_L1Cache.reset();
            tl_L1Initialized = false;
        }
    }

    void refreshL1FromL2()
    {
        ensureL1Cache();
    }

private:
    crypto::X509CertPtr enrichCertificate(const CertFingerprint& fingerprint, const std::string& policy, const std::string& publicKey)
    {
        // TODO: Implement certificate re-signing logic

        static_cast<void>(fingerprint);
        static_cast<void>(policy);
        static_cast<void>(publicKey);

        return nullptr;
    }

    void promoteToL1(const CertFingerprint& fingerprint, crypto::X509CertPtr value, Clock::time_point now)
    {
        auto expiry = now + config.l1Ttl;
        tl_L1Cache->put(fingerprint, std::move(value), expiry);
    }
};

} // namespace snet::pki