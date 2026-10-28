#pragma once

#include <atomic>
#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <tuple>

#include <snet/layers/l3/ip_address.hpp>
#include <snet/session/session_manager.hpp>
#include <snet/tcp/tcp_stream.hpp>
#include <snet/tcp/tcp_transmit_handler.hpp>
#include <snet/tcp/tcp_receive_handler.hpp>

#include <snet/probe/probe_context.hpp>
#include <snet/probe/probe_owner.hpp> // IProbeOwner
#include <snet/probe/probe_registry.hpp>
#include <snet/probe/probe_handle.hpp>
#include <snet/probe/probe_result.hpp>

namespace snet::probe
{

struct ProbeConfig
{
    std::chrono::milliseconds connectTimeout{1000};
    std::chrono::milliseconds handshakeTimeout{2000};
    uint16_t sourcePortMin{40000};
    uint16_t sourcePortMax{60000};
    uint32_t initialIssSeed{0}; // 0 = random_device
};

template <typename SessionManagerType>
class ProbeConnector : public IProbeOwner
{
public:
    using Session = typename SessionManagerType::Session;
    using TcpConnection = snet::tcp::TcpConnection;
    using TxHandler = snet::tcp::TcpTransmitHandler<SessionManagerType>;

    ProbeConnector(SessionManagerType& probeMgr, TxHandler& tx, ProbeRegistry& registry, tls::RecordPool& pool,
                   ProbeConfig cfg = ProbeConfig{});

    /// @brief Start a probe to (serverIP:serverPort) from sourceIP.
    std::shared_ptr<ProbeHandle> start(std::string sni, layers::IPAddress serverIP, uint16_t serverPort,
                                       layers::IPAddress sourceIP, ProbeConnectionCallback cb);

    void finalizeProbe(void* session, uint32_t key, const ProbeKey& flowKey) override;
    void abortProbe(void* session, uint32_t key, const ProbeKey& flowKey, std::string_view reason) override;

private:
    uint16_t pickEphemeralPort();
    static uint32_t hashFlow(const layers::IPAddress& src, uint16_t sport, const layers::IPAddress& dst,
                             uint16_t dport);

    SessionManagerType& probeMgr_;
    TxHandler& tx_;
    ProbeRegistry& registry_;
    tls::RecordPool& pool_;
    ProbeConfig cfg_;
    std::mt19937 rng_;
    std::atomic<uint16_t> nextPort_;
};


template <typename SessionManagerType>
ProbeConnector<SessionManagerType>::ProbeConnector(SessionManagerType& probeMgr,
                                                   snet::tcp::TcpTransmitHandler<SessionManagerType>& tx,
                                                   ProbeRegistry& registry, tls::RecordPool& pool, ProbeConfig cfg)
    : probeMgr_(probeMgr)
    , tx_(tx)
    , registry_(registry)
    , pool_(pool)
    , cfg_(cfg)
    , rng_(cfg.initialIssSeed ? cfg.initialIssSeed : std::random_device{}())
{
    std::uniform_int_distribution<uint16_t> d(cfg_.sourcePortMin, cfg_.sourcePortMax);
    nextPort_.store(d(rng_));
}

template <typename SessionManagerType>
uint16_t ProbeConnector<SessionManagerType>::pickEphemeralPort()
{
    return nextPort_.fetch_add(1);
}

template <typename SessionManagerType>
uint32_t ProbeConnector<SessionManagerType>::hashFlow(const layers::IPAddress& src, uint16_t sport,
                                                      const layers::IPAddress& dst, uint16_t dport)
{
    return layers::hash5Tuple(src, dst, sport, dport, layers::IPProto::TCP, /*bidirectional=*/false);
}

template <typename SessionManagerType>
std::shared_ptr<ProbeHandle> ProbeConnector<SessionManagerType>::start(std::string sni, layers::IPAddress serverIP,
                                                                       uint16_t serverPort, layers::IPAddress sourceIP,
                                                                       ProbeConnectionCallback cb)
{
    const uint16_t sourcePort = this->pickEphemeralPort();
    const uint32_t key = ProbeConnector<SessionManagerType>::hashFlow(sourceIP, sourcePort, serverIP, serverPort);

    auto* session = probeMgr_.findOrCreate(key);
    if (!session)
    {
        ProbeResult r;
        r.status = ProbeResult::Status::ConnectFailed;
        r.error = "probe session create failed";
        cb(std::move(r));
        return nullptr;
    }

    auto* probe = probeMgr_.template getContext<ProbeContext>(session);
    if (!probe)
    {
        ProbeResult r;
        r.status = ProbeResult::Status::ConnectFailed;
        r.error = "probe context missing (factory not installed?)";
        cb(std::move(r));
        return nullptr;
    }
    probe->tlsPool = std::make_unique<tls::RecordPool>(8);
    probe->tls = std::make_unique<tls::Session>(*probe->tlsPool);
    probe->tls->setVersion(tls::ProtocolVersion::TLSv1_2);
    probe->sni = std::move(sni);
    probe->cb = std::move(cb);

    auto* conn = probeMgr_.template getContext<TcpConnection>(session, 0);
    if (!conn)
    {
        ProbeResult r;
        r.status = ProbeResult::Status::ConnectFailed;
        r.error = "probe TcpConnection ctx missing";
        probe->cb(std::move(r));
        return nullptr;
    }

    conn->localIP = sourceIP;
    conn->localPort = sourcePort;
    conn->remoteIP = serverIP;
    conn->remotePort = serverPort;
    conn->passiveOpen = false;

    conn->rcvWnd = conn->rxRing ? static_cast<uint32_t>(conn->rxRing->freeSpace()) : 65535;
    if (conn->rcvWnd > 65535)
        conn->rcvWnd = 65535;

    const uint32_t iss = static_cast<uint32_t>(rng_());
    auto syn = snet::tcp::TcpStateMachine::onActiveOpen(*conn, iss);
    if (syn.type == snet::tcp::TcpOutput::Type::None)
    {
        ProbeResult r;
        r.status = ProbeResult::Status::ConnectFailed;
        r.error = "onActiveOpen failed (state not Closed?)";
        probe->cb(std::move(r));
        return nullptr;
    }

    ProbeHandle::Config hcfg{cfg_.connectTimeout, cfg_.handshakeTimeout};
    std::shared_ptr<ProbeHandle> handle(
        new ProbeHandle(this,
                        static_cast<void*>(session),
                        key,
                        ProbeKey{sourceIP.toIPv4(), sourcePort, serverIP.toIPv4(), serverPort},
                        hcfg));
    probe->handle = handle;

    registry_.add(ProbeKey{sourceIP.toIPv4(), sourcePort, serverIP.toIPv4(), serverPort});

    conn->pendingOutput = syn;
    conn->hasPendingOutput = true;
    tx_.pump(session);

    handle->armTimers();
    return handle;
}

template <typename SessionManagerType>
void ProbeConnector<SessionManagerType>::finalizeProbe(void* session, uint32_t key, const ProbeKey& flowKey)
{
    registry_.remove(flowKey);

    auto* s = static_cast<Session*>(session);
    if (!s)
        return;

    tx_.closeConnection(s);
    probeMgr_.removeSession(key);
}

template <typename SessionManagerType>
void ProbeConnector<SessionManagerType>::abortProbe(void* session, uint32_t key, const ProbeKey& flowKey,
                                                    std::string_view reason)
{
    registry_.remove(flowKey);

    auto* s = static_cast<Session*>(session);
    if (!s)
        return;

    auto* probe = probeMgr_.template getContext<ProbeContext>(s);
    if (probe && !probe->done.exchange(true) && probe->cb)
    {
        ProbeResult r;
        r.status = ProbeResult::Status::ConnectTimeout;
        r.error = std::string(reason);
        probe->cb(std::move(r));
    }

    tx_.abortConnection(s);
    probeMgr_.removeSession(key);
}

} // namespace snet::probe