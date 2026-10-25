#pragma once

#include <atomic>
#include <memory>
#include <string>

#include <snet/tls/session.hpp>
#include <snet/tls/record_pool.hpp>
#include <snet/probe/probe_result.hpp>
#include <snet/probe/probe_handle.hpp>

namespace snet::probe
{

struct ProbeContext
{
    static constexpr size_t MAX_INSTANCES = 1;

    std::string                   sni;
    std::unique_ptr<tls::RecordPool> tlsPool;
    std::unique_ptr<tls::Session> tls;
    ProbeResult                   result;
    ProbeConnectionCallback       cb;
    std::atomic<bool>             done{false};
    std::atomic<bool>             aborted{false};
    std::atomic<bool>             clientHelloSent{false};
    std::weak_ptr<ProbeHandle>    handle;
};

} // namespace snet::probe