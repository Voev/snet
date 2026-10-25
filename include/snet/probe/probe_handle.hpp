#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

#include <snet/probe/probe_registry.hpp>    // ProbeKey
#include <snet/probe/probe_owner.hpp>       // IProbeOwner

namespace snet::probe
{

/// @brief RAII handle for a single probe.
///
/// Owns the watchdog. complete()/abort() are idempotent and thread-safe.
/// MUST be created via std::make_shared? No — via `new` from
/// ProbeConnector<T>::start (ctor is public, not friend).
class ProbeHandle : public std::enable_shared_from_this<ProbeHandle>
{
public:
    struct Config
    {
        std::chrono::milliseconds connectTimeout{1000};
        std::chrono::milliseconds handshakeTimeout{2000};
    };

    ProbeHandle(IProbeOwner* owner, void* session, uint32_t key,
                ProbeKey flowKey, Config cfg);

    ~ProbeHandle();

    ProbeHandle(const ProbeHandle&)            = delete;
    ProbeHandle& operator=(const ProbeHandle&) = delete;

    void complete() noexcept;
    void abort(std::string_view reason) noexcept;
    void armTimers();

private:
    IProbeOwner*             owner_{nullptr};
    void*                    session_{nullptr};
    uint32_t                 key_{0};
    ProbeKey                 flowKey_{};
    Config                   cfg_{};

    std::atomic<bool>        completed_{false};
    std::thread              watchdog_;
    std::condition_variable  cv_;
    std::mutex               mtx_;
    bool                     stop_{false};
};

} // namespace snet::probe