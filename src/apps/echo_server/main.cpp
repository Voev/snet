// main.cpp
#include <cstdio>
#include <memory>

#include <snet/session/session_manager.hpp>
#include <snet/session/session_pipeline.hpp>
#include <snet/tcp/tcp_listener_handler.hpp>
#include <snet/tcp/tcp_receive_handler.hpp>
#include <snet/tcp/tcp_transmit_handler.hpp>
#include <snet/tcp/tcp_listener.hpp>
#include <snet/layers/packet_sink.hpp>
#include <snet/layers/l3/ip_address.hpp>

#include "echo_consumer.hpp"

using namespace snet::layers;
using namespace snet::tcp;
using namespace echo;

using SessionContexts = std::tuple<TcpConnection>;
using SessionManager = snet::session::SessionManager<uint32_t, SessionContexts>;

// ============================================================
// Sink: real network interface
// ============================================================
class NetworkSink : public IPacketSink
{
public:
    bool transmit(Packet* packet) override
    {
        // In production: AF_PACKET / DPDK / TUN / etc.
        // Here — just log
        printf("[TX] %zu bytes\n", packet->getDataLen());

        // Example with AF_PACKET:
        // ::sendto(rawSocket_, data, len, 0, ...);
        return true;
    }
};

// ============================================================
// Main
// ============================================================
int main()
{
    printf("=== TCP Echo Server ===\n\n");

    // ---------- 1. SessionManager ----------
    SessionManager::Config sessCfg;
    sessCfg.max_sessions = 10000;
    SessionManager mgr(sessCfg);

    NetworkSink sink;
    TcpListenerRegistry listeners;
    listeners.add(IPAddress::any(), 8080);   // listen on 0.0.0.0:8080

    auto echoConsumer = std::make_unique<EchoConsumer<SessionManager>>(&mgr);

    auto rxPool = std::make_unique<RxRingPool>(1024);
    auto txPool = std::make_unique<TxRingPool>(1024);

    auto pipeline = std::make_unique<SessionManager::Pipeline>();

    pipeline->addHandler<TcpListenerHandler<SessionManager>>(&listeners);
    pipeline->addHandler<TcpReceiveHandler<SessionManager>>(rxPool.get(), nullptr, echoConsumer.get());
    pipeline->addHandler<TcpTransmitHandler<SessionManager>>(&sink, txPool.get());

    mgr.setPipeline(std::move(pipeline));
    return 0;
}