#include <snet/probe/probe_handle.hpp>
#include <snet/probe/probe_owner.hpp>

#include <casket/log/log.hpp>

namespace snet::probe
{

ProbeHandle::ProbeHandle(IProbeOwner* owner, void* session, uint32_t key,
                         ProbeKey flowKey, Config cfg)
    : owner_(owner)
    , session_(session)
    , key_(key)
    , flowKey_(flowKey)
    , cfg_(cfg)
{
}

ProbeHandle::~ProbeHandle()
{
    {
        std::lock_guard lk(mtx_);
        stop_ = true;
    }
    cv_.notify_all();
    if (watchdog_.joinable())
        watchdog_.join();

    if (!completed_.exchange(true) && owner_)
    {
        try { owner_->abortProbe(session_, key_, flowKey_, "handle destroyed"); }
        catch (...) {}
    }
}

void ProbeHandle::complete() noexcept
{
    if (completed_.exchange(true)) return;

    {
        std::lock_guard lk(mtx_);
        stop_ = true;
    }
    cv_.notify_all();

    if (owner_)
    {
        try { owner_->finalizeProbe(session_, key_, flowKey_); }
        catch (...) {}
    }
}

void ProbeHandle::abort(std::string_view reason) noexcept
{
    if (completed_.exchange(true)) return;

    {
        std::lock_guard lk(mtx_);
        stop_ = true;
    }
    cv_.notify_all();

    if (owner_)
    {
        try { owner_->abortProbe(session_, key_, flowKey_, reason); }
        catch (...) {}
    }
}

void ProbeHandle::armTimers()
{
    auto self = weak_from_this();
    auto cfg  = cfg_;

    watchdog_ = std::thread([self, cfg]()
    {
        auto lock = self.lock();
        if (!lock) return;
        auto& h = *lock;

        const auto deadline = std::chrono::steady_clock::now()
                            + cfg.connectTimeout + cfg.handshakeTimeout;

        std::unique_lock lk(h.mtx_);
        while (!h.stop_)
        {
            if (h.cv_.wait_until(lk, deadline) == std::cv_status::timeout)
            {
                lk.unlock();
                h.abort("probe timeout");
                return;
            }
        }
    });
}

} // namespace snet::probe