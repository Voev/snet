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
#include <snet/crypto/cert.hpp>
/// @todo
#include <snet/pki/ttl_cache.hpp>

namespace snet::pki
{

using CacheKey = uint64_t;

using L1Cache = casket::TtlCache<CacheKey, crypto::X509CertPtr>;

using L2Cache = casket::concurrency::TtlCache<CacheKey, crypto::X509CertPtr>;

struct CacheConfig
{
    std::chrono::seconds l1Ttl{3600};     // L1 cache TTL
    std::chrono::seconds l2Ttl{300};      // L2 cache TTL
    std::chrono::seconds staleTtl{86400}; // Stale TTL для fallback
    size_t workerThreads{4};
    size_t batchSize{8};
    std::chrono::milliseconds queueTimeout{100};
    std::chrono::milliseconds popTimeout{10}; // Таймаут для pop операции
};

class WorkerPool
{
public:
    using Clock = std::chrono::steady_clock;
    using EnricherFunc =
        std::function<crypto::X509CertPtr(const CacheKey&, const std::string& policy, const std::string& originCert)>;

    struct EnrichmentTask
    {
        CacheKey key;
        std::string policy;
        std::string originCert;
        Clock::time_point enqueueTime;
        uint64_t attempt = 0;

        EnrichmentTask() = default;
        EnrichmentTask(CacheKey k, std::string p, std::string cert)
            : key(k)
            , policy(std::move(p))
            , originCert(std::move(cert))
            , enqueueTime(Clock::now())
        {
        }
    };

    WorkerPool(EnricherFunc enricher, L2Cache* l2, const CacheConfig& cfg = CacheConfig{})
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

    // Отправить запрос на обогащение
    void enrichAsync(const CacheKey& key, const std::string& policy, const std::string& cert)
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

            // Собираем батч с таймаутом
            auto startTime = Clock::now();

            while (batch.size() < config.batchSize)
            {
                // Используем pop с небольшим таймаутом через периодическую проверку
                auto popResult = requestQueue.pop();
                if (popResult.has_value())
                {
                    batch.push_back(std::move(popResult.value()));
                }

                // Если очередь пуста и прошло достаточно времени - выходим
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
                // Проверяем дубликаты (key может обрабатываться другим воркером)
                auto now = Clock::now();
                auto existing = l2Cache->get(task.key, now);
                if (existing)
                {
                    // Уже есть в кэше - пропускаем
                    continue;
                }

                if (auto enrichedValue = enricher(task.key, task.policy, task.originCert))
                {
                    auto expiry = now + config.l2Ttl;

                    l2Cache->put(task.key, std::move(enrichedValue), expiry);
                    totalProcessed++;
                }
                else
                {
                    totalFailed++;
                    std::cerr << "Enricher returned null for key: " << task.key << std::endl;
                }
            }
            catch (const std::exception& e)
            {
                totalFailed++;
                std::cerr << "Enrichment failed for key: " << task.key << ", attempt: " << task.attempt
                          << ", error: " << e.what() << std::endl;

                // Retry logic with exponential backoff
                if (task.attempt < 3)
                {
                    task.attempt++;
                    task.enqueueTime = Clock::now();
                    requestQueue.push(task);

                    // Экспоненциальная задержка перед повторной попыткой
                    std::this_thread::sleep_for(std::chrono::milliseconds(100 * (1 << task.attempt)));
                }
            }

            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start);

            if (duration > std::chrono::seconds(5))
            {
                std::cerr << "Slow enrichment for key: " << task.key << ", took " << duration.count() << "ms"
                          << std::endl;
            }
        }
    }

private:
    casket::lock_free::Queue<EnrichmentTask> requestQueue;
    std::vector<std::thread> workers;
    std::atomic<bool> running{true};

    EnricherFunc enricher;
    L2Cache* l2Cache;
    CacheConfig config;

    // Статистика
    std::atomic<uint64_t> totalProcessed{0};
    std::atomic<uint64_t> totalFailed{0};
};

class CertCache
{
private:
    using Clock = std::chrono::steady_clock;

    L2Cache l2Cache;
    WorkerPool workerPool;
    CacheConfig config;

    // Thread-local storage для L1 кэша
    static inline thread_local std::unique_ptr<L1Cache> tL1Cache;
    static inline thread_local Clock::time_point tLastL2Refresh;
    static inline thread_local bool tL1Initialized = false;

    void ensureL1Cache()
    {
        if (!tL1Initialized)
        {
            tL1Cache = std::make_unique<L1Cache>(1024); // 1024 entries
            tL1Initialized = true;
            tLastL2Refresh = Clock::now();
        }
    }

public:
    CertCache(const CacheConfig& cfg = CacheConfig{})
        : l2Cache(256, cfg.l2Ttl)
        , workerPool([this](const CacheKey& key, const std::string& policy, const std::string& cert)
                     { return enrichCertificate(key, policy, cert); }, &l2Cache, cfg)
        , config(cfg)
    {
    }

    crypto::X509CertPtr get(X509Cert* originCert, const std::string& policy, const std::string& cert)
    {
        if (!originCert)
            return nullptr;

        ensureL1Cache();

        auto key = crypto::Cert::computeHash(originCert, EVP_sha1());
        auto now = Clock::now();

        // L1 lookup (очень быстрый)
        if (auto value = tL1Cache->get(key, now))
        {
            return crypto::Cert::shallowCopy(*value);
        }

        // L2 lookup
        if (auto val = l2Cache.get(key, now))
        {
            // Продвигаем в L1 для быстрого доступа
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

            // Минимальный sleep для предотвращения busy-waiting
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }

    // Получение статистики
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

    // Очистка thread-local кэша для текущего потока
    static void clearThreadLocalCache()
    {
        if (tL1Initialized)
        {
            tL1Cache.reset();
            tL1Initialized = false;
        }
    }

    // Принудительное обновление из L2 в L1 для текущего потока
    void refreshL1FromL2()
    {
        ensureL1Cache();

        // TODO: Реализовать логику обновления L1 из L2
        // Например, можно пройтись по горячим ключам
    }

private:
    crypto::X509CertPtr enrichCertificate(const CacheKey& key, const std::string& policy, const std::string& publicKey)
    {
        // Реальная логика переподписи сертификата
        // TODO: Implement certificate re-signing logic

        static_cast<void>(key);
        static_cast<void>(policy);
        static_cast<void>(publicKey);

        // Пример реализации:
        // 1. Получить оригинальный сертификат из хранилища по key
        // 2. Создать CSR из оригинального сертификата
        // 3. Переподписать с использованием policy
        // 4. Вернуть новый сертификат

        // Пока возвращаем nullptr
        return nullptr;
    }

    void promoteToL1(const CacheKey& key, crypto::X509CertPtr value, Clock::time_point now)
    {
        auto expiry = now + config.l1Ttl;
        tL1Cache->put(key, std::move(value), expiry);
    }
};

} // namespace snet::pki