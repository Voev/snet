#pragma once
#include <chrono>
#include <memory>
#include <casket/types/ttl_cache.hpp>
#include <snet/crypto/cert.hpp>

namespace snet::pki
{

class WorkerPool {
private:
    using Clock = std::chrono::steady_clock;
    using EnricherFunc = std::function<crypto::X509CertPtr(const Key&)>;
    
    struct EnrichmentTask {
        uint64_t key;
        std::string base64Request;
        std::chrono::steady_clock::time_point enqueue_time;
        uint64_t attempt = 0;
    };
    
    moodycamel::ConcurrentQueue<Key> request_queue;
    std::vector<std::thread> workers;
    std::atomic<bool> running{true};
    
    EnricherFunc enricher;
    L2Cache<Key, Value>* l2_cache;
    CacheMetrics* metrics;
    CacheConfig config;
    
public:
    EnrichmentWorkerPool(EnricherFunc enricher, 
                         L2Cache<Key, Value>* l2,
                         CacheMetrics* metrics,
                         const CacheConfig& config)
        : enricher(std::move(enricher)), l2_cache(l2), metrics(metrics), config(config) {
        
        for (size_t i = 0; i < config.worker_threads; ++i) {
            workers.emplace_back([this](std::stop_token stoken) {
                worker_loop(stoken);
            });
        }
    }
    
    ~EnrichmentWorkerPool() {
        running = false;
        workers.clear();  // jthread автоматически join'ятся
    }
    
    // Отправить запрос на обогащение
    void enrich_async(const Key& key) {
        request_queue.enqueue(key);
        metrics->enrichments_requested++;
    }
    
private:
    void worker_loop(std::stop_token stoken) {
        std::vector<Key> batch;
        batch.reserve(config.batch_size);
        
        while (!stoken.stop_requested() && running) {
            // Собираем батч
            batch.clear();
            Key key;
            size_t collected = 0;
            
            while (collected < config.batch_size && request_queue.try_dequeue(key)) {
                batch.push_back(std::move(key));
                collected++;
            }
            
            if (batch.empty()) {
                std::this_thread::sleep_for(config.worker_poll_interval);
                continue;
            }
            
            // Обрабатываем батч
            process_batch(batch);
        }
    }
    
    void process_batch(const std::vector<Key>& batch) {
        for (const auto& key : batch) {
            auto start = std::chrono::steady_clock::now();
            
            try {
                // ВЫЗОВ ПОЛЬЗОВАТЕЛЬСКОГО ЭНРИЧЕРА (сеть, диск, CPU)
                if (auto enriched_value = enricher(key)) {
                    auto expiry = Clock::now() + config.default_ttl;
                    auto stale_until = expiry + config.stale_ttl;
                    
                    l2_cache->put(key, std::move(*enriched_value), expiry, stale_until);
                    metrics->enrichments_completed++;
                    
                    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
                        std::chrono::steady_clock::now() - start);
                    
                    // Exponential moving average
                    auto old_avg = metrics->avg_enrichment_time.load();
                    auto new_avg = old_avg + (duration - old_avg) / 100;
                    metrics->avg_enrichment_time.store(new_avg);
                } else {
                    metrics->enrichments_failed++;
                }
            } catch (const std::exception& e) {
                metrics->enrichments_failed++;
                if (config.enable_tracing) {
                    std::cerr << "Enrichment failed for key: " << key << ", error: " << e.what() << std::endl;
                }
            }
        }
    }
};

template <typename Key, typename Value>
class EnterpriseAsyncCache
{
private:
    using Clock = std::chrono::steady_clock;

    CacheConfig config;
    CacheMetrics metrics;

    casket::TtlCache<uint64_t, crypto::X509CertPtr> l2_cache;
    EnrichmentWorkerPool<Key, Value> worker_pool;

    // Thread-local storage
    static inline thread_local std::unique_ptr<casket::TtlCache<uint64_t, crypto::X509CertPtr>> t_l1_cache;
    static inline thread_local Clock::time_point t_last_l2_refresh;

public:
    EnterpriseAsyncCache(CacheConfig cfg = {}, std::function<std::optional<Value>(const Key&)> enricher = nullptr)
        : config(std::move(cfg))
        , l2_cache(config.l2_cache_size, config.eviction_policy)
        , worker_pool(std::move(enricher), &l2_cache, &metrics, config)
    {

        static_assert(std::is_copy_constructible<Key>::value, "Key must be copy constructible");

        if (config.enable_metrics)
        {
            start_metrics_reporter();
        }
    }

    // ========================================================================
    // PUBLIC API for worker threads
    // ========================================================================

    // Основной метод получения данных (non-blocking)
    X509CertPtr get(X509Cert* originCert)
    {
        X509_NAME_hash

        // L1 lookup (zero-contention, ~5ns)
        init_thread_cache();
        auto now = Clock::now();

        if (auto* val = t_l1_cache->get(key, now))
        {
            metrics.l1_hits++;
            return *val;
        }
        metrics.l1_misses++;

        // L2 lookup (shared_lock, ~50ns)
        auto [val, is_hit] = l2_cache.get(key, now);
        if (val)
        {
            metrics.l2_hits++;
            promote_to_l1(key, *val, now);
            return *val;
        }
        metrics.l2_misses++;

        /// origin -> csr
        /// get policy

        // Cache miss - отправляем запрос на обогащение
        worker_pool.enrich_async(csr, policy);

        return std::nullopt;
    }

    // Версия с ожиданием (blocking, для синхронных сценариев)
    std::optional<Value> get_blocking(const Key& key, std::chrono::milliseconds timeout)
    {
        auto start = Clock::now();

        while (true)
        {
            if (auto val = get(key))
            {
                return val;
            }

            if (Clock::now() - start > timeout)
            {
                return std::nullopt;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    // Предзагрузка данных (fire-and-forget)
    void prefetch(const Key& key)
    {
        worker_pool.enrich_async(key);
    }

    // Инвалидация
    void invalidate(const Key& key)
    {
        // В реальном коде нужно очистить и L1, и L2
        // L1 чистим через паттерн "генерационный номер"
    }

    // Метрики
    CacheMetrics get_metrics() const
    {
        metrics.current_l2_size = l2_cache.size();
        return metrics;
    }

private:
    void init_thread_cache()
    {
        if (!t_l1_cache)
        {
            t_l1_cache = std::make_unique<L1Cache<Key, Value>>(config.l1_cache_size);
        }

        // Периодически обновляем L1 из L2 (для синхронизации)
        auto now = Clock::now();
        if (now - t_last_l2_refresh > std::chrono::seconds(1))
        {
            t_last_l2_refresh = now;
            // В production: инкрементальное обновление L1 из L2
        }
    }

    void promote_to_l1(const Key& key, const Value& value, Clock::time_point now)
    {
        Value copy = value; // Копируем в L1 (или move, если возможно)
        auto expiry = now + config.default_ttl;
        t_l1_cache->put(key, std::move(copy), expiry);
    }

    void start_metrics_reporter()
    {
        static std::jthread reporter(
            [this](std::stop_token stoken)
            {
                while (!stoken.stop_requested())
                {
                    std::this_thread::sleep_for(config.metrics_report_interval);

                    if (config.enable_tracing)
                    {
                        auto stats = get_metrics();
                        std::cout << stats.to_prometheus() << std::endl;
                    }
                }
            });
    }
};

} // namespace snet::pki