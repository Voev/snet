#pragma once
#include <chrono>
#include <optional>
#include <memory>
#include <atomic>
#include <cassert>
#include <type_traits>
#include <casket/lock_free/lf_hash_table.hpp>

namespace casket::concurrency
{

template <typename Key, typename Value>
class TtlCache
{
public:
    using Clock = std::chrono::steady_clock;
    using TimePoint = Clock::time_point;
    using Duration = Clock::duration;

    struct CacheEntry
    {
        Value value;
        TimePoint expiry;

        CacheEntry() = default;

        template <typename... Args>
        CacheEntry(Args&&... args)
            : value(std::forward<Args>(args)...)
            , expiry()
        {
        }

        CacheEntry(Value val, TimePoint exp)
            : value(std::move(val))
            , expiry(exp)
        {
        }

        CacheEntry(const CacheEntry&) = delete;
        CacheEntry& operator=(const CacheEntry&) = delete;
        
        CacheEntry(CacheEntry&&) = default;
        CacheEntry& operator=(CacheEntry&&) = default;
    };

    explicit TtlCache(size_t maxSize = 256, Duration defaultTtl = std::chrono::seconds(300))
        : cache_(maxSize * 2)  // Увеличиваем размер пула для хранения
        , maxSize_(maxSize)
        , defaultTtl_(defaultTtl)
    {
    }

    // Вставка с TTL
    void put(const Key& key, Value value, Duration ttl)
    {
        auto now = Clock::now();
        put(key, std::move(value), now + ttl);
    }

    // Вставка с точкой истечения
    void put(const Key& key, Value value, TimePoint expiry)
    {
        // Сначала проверяем существование и удаляем если есть
        remove(key);
        
        // Проверяем размер и делаем eviction если нужно
        if (cache_.size() >= maxSize_) {
            evictOne();
        }
        
        // Вставляем новое значение
        cache_.put(key, CacheEntry(std::move(value), expiry));
    }

    // Получение значения
    Value* get(const Key& key)
    {
        auto now = Clock::now();
        
        auto* entry = cache_.get(key);
        if (!entry) {
            return nullptr;
        }
        
        // Проверяем не истекло ли значение
        if (now > entry->expiry) {
            // Асинхронное удаление (не блокирует)
            cache_.remove(key);
            return nullptr;
        }
        
        return &entry->value;
    }

    // Получение значения с проверкой времени
    Value* get(const Key& key, TimePoint now)
    {
        auto* entry = cache_.get(key);
        if (!entry) {
            return nullptr;
        }
        
        if (now > entry->expiry) {
            cache_.remove(key);
            return nullptr;
        }
        
        return &entry->value;
    }

    // Получение с копированием (только для copyable типов)
    template <typename U = Value>
    std::enable_if_t<std::is_copy_constructible_v<U>, std::optional<U>> 
    getCopy(const Key& key)
    {
        auto* value = get(key);
        if (value) {
            return *value;
        }
        return std::nullopt;
    }

    // Получение с перемещением (извлекает и удаляет)
    std::optional<Value> take(const Key& key)
    {
        auto* entry = cache_.get(key);
        if (!entry) {
            return std::nullopt;
        }
        
        auto now = Clock::now();
        if (now > entry->expiry) {
            cache_.remove(key);
            return std::nullopt;
        }
        
        // Перемещаем значение
        Value value = std::move(entry->value);
        cache_.remove(key);
        return std::move(value);
    }

    // Удаление значения
    bool remove(const Key& key)
    {
        return cache_.remove(key);
    }

    // Очистка всех устаревших записей
    size_t cleanup()
    {
        auto now = Clock::now();
        std::vector<Key> toRemove;
        
        // Собираем ключи для удаления
        cache_.forEach([&](const Key& key, CacheEntry& entry) {
            if (now > entry.expiry) {
                toRemove.push_back(key);
            }
        });
        
        // Удаляем истекшие записи
        for (const auto& key : toRemove) {
            cache_.remove(key);
        }
        
        return toRemove.size();
    }

    // Очистка всего кэша
    void clear()
    {
        cache_.clear();
    }

    // Получение размера
    size_t size() const
    {
        return cache_.size();
    }

    // Проверка наличия ключа
    bool contains(const Key& key) const
    {
        auto* entry = cache_.get(key);
        if (!entry) {
            return false;
        }
        
        auto now = Clock::now();
        return now <= entry->expiry;
    }

    // Обновление TTL для ключа
    bool touch(const Key& key, Duration newTtl)
    {
        auto* entry = cache_.get(key);
        if (!entry) {
            return false;
        }
        
        auto now = Clock::now();
        entry->expiry = now + newTtl;
        return true;
    }

    // Получение оставшегося времени жизни
    std::optional<Duration> getRemainingTtl(const Key& key) const
    {
        auto* entry = cache_.get(key);
        if (!entry) {
            return std::nullopt;
        }
        
        auto now = Clock::now();
        if (now >= entry->expiry) {
            return std::nullopt;
        }
        
        return entry->expiry - now;
    }

    // Проверка существования без обновления
    bool exists(const Key& key) const
    {
        auto* entry = cache_.get(key);
        if (!entry) {
            return false;
        }
        
        auto now = Clock::now();
        return now <= entry->expiry;
    }

private:
    void evictOne()
    {
        // Простая стратегия - удаляем самую старую запись
        Key oldestKey{};
        TimePoint oldestExpiry = Clock::now() + std::chrono::hours(24); // Очень большое значение
        
        cache_.forEach([&](const Key& key, CacheEntry& entry) {
            if (entry.expiry < oldestExpiry) {
                oldestExpiry = entry.expiry;
                oldestKey = key;
            }
        });
        
        cache_.remove(oldestKey);
    }

private:
    casket::lf::HashTable<Key, CacheEntry> cache_;
    size_t maxSize_;
    Duration defaultTtl_;
};

} // namespace casket::concurrency