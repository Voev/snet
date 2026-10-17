#pragma once

#include <chrono>
#include <optional>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>

#include "proxy_types.hpp"

namespace snet::proxy
{

/// Кэш решений по SNI.
///
/// Без кэша каждый cache-miss запускал бы probe. С кэшем — probe
/// делается один раз на SNI (per TTL), дальше решение берётся из
/// памяти. Это критично для high-load: 99% решений должны быть hit.
class DecisionCache
{
public:
    struct Config
    {
        std::chrono::seconds ttl{300};
        size_t               maxEntries{100000};
    };

    DecisionCache()
        : DecisionCache(Config{})
    {
    }

    explicit DecisionCache(Config cfg)
        : cfg_(cfg)
    {
    }

    std::optional<InspectionDecision> lookup(const std::string& sni) const
    {
        const auto now = std::chrono::steady_clock::now();

        std::shared_lock lock(mtx_);
        const auto it = map_.find(sni);
        if (it == map_.end())
            return std::nullopt;
        if (it->second.expires < now)
            return std::nullopt;
        return it->second.decision;
    }

    void store(const std::string& sni, InspectionDecision d)
    {
        std::unique_lock lock(mtx_);

        // Простая эвикция: при переполнении чистим всё.
        // TODO: заменить на LRU, если maxEntries реально нагружен.
        if (map_.size() >= cfg_.maxEntries
            && map_.find(sni) == map_.end())
        {
            map_.clear();
        }

        map_[std::string(sni)] = Entry{
            d, std::chrono::steady_clock::now() + cfg_.ttl};
    }

    void clear()
    {
        std::unique_lock lock(mtx_);
        map_.clear();
    }

    size_t size() const
    {
        std::shared_lock lock(mtx_);
        return map_.size();
    }

private:
    struct Entry
    {
        InspectionDecision                    decision;
        std::chrono::steady_clock::time_point expires;
    };

    Config                                  cfg_;
    mutable std::shared_mutex               mtx_;
    std::unordered_map<std::string, Entry>  map_;
};

} // namespace snet::proxy