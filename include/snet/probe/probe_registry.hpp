#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <shared_mutex>
#include <unordered_set>

#include <snet/layers/l3/ip_address.hpp>

namespace snet::probe
{

/// @brief 5-tuple identifying an active probe flow.
///
/// XDP dispatcher checks this registry on every packet to decide
/// whether the packet belongs to a probe session (→ probe SessionManager)
/// or to a client session (→ client SessionManager).
struct ProbeKey
{
    layers::IPv4Address srcIP;
    uint16_t srcPort;
    layers::IPv4Address dstIP;
    uint16_t dstPort;

    bool operator==(const ProbeKey&) const = default;
};

struct ProbeKeyHash
{
    size_t operator()(const ProbeKey& k) const noexcept
    {
        size_t h = std::hash<uint32_t>{}(k.srcIP.toNetwork());
        h ^= std::hash<uint16_t>{}(k.srcPort) + 0x9e3779b9u + (h << 6) + (h >> 2);
        h ^= std::hash<uint32_t>{}(k.dstIP.toNetwork()) + 0x9e3779b9u + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(k.dstPort) + 0x9e3779b9u + (h << 6) + (h >> 2);
        return h;
    }
};

/// @brief Thread-safe registry of active probe flows.
///
/// `contains()` is on the hot path (every packet), so the common case
/// must be a cheap shared-lock + hash lookup.
class ProbeRegistry
{
public:
    void add(const ProbeKey& k)
    {
        std::unique_lock lk(mtx_);
        keys_.insert(k);
    }

    void remove(const ProbeKey& k)
    {
        std::unique_lock lk(mtx_);
        keys_.erase(k);
    }

    bool contains(const ProbeKey& k) const
    {
        std::shared_lock lk(mtx_);
        return keys_.contains(k);
    }

    size_t size() const
    {
        std::shared_lock lk(mtx_);
        return keys_.size();
    }

private:
    mutable std::shared_mutex mtx_;
    std::unordered_set<ProbeKey, ProbeKeyHash> keys_;
};

} // namespace snet::probe