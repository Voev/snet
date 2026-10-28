#include <iostream>

#include <casket/thread/pool.hpp>
#include <casket/opt/opt.hpp>
#include <casket/log/log.hpp>

#include <casket/signal/signal_handler.hpp>

#include <snet/io.hpp>
#include <snet/arp.hpp>

#include <snet/pp/packet_pipeline.hpp>
#include <snet/pp/l2_filter_stage.hpp>
#include <snet/pp/arp_stage.hpp>
#include <snet/pp/routing_stage.hpp>
#include <snet/pp/ip_forward_stage.hpp>
#include <snet/pp/session_stage.hpp>
#include <snet/pp/forward_stage.hpp>

#include <snet/io.hpp>
#include <snet/layers.hpp>
#include <snet/session.hpp>

#include <snet/tcp/tcp_conn_ctx_factory.hpp>
#include <snet/tcp/tcp_listener_handler.hpp>
#include <snet/tcp/tcp_receive_handler.hpp>
#include <snet/tcp/tcp_transmit_handler.hpp>
#include <snet/tcp/tcp_listener.hpp>

#include <snet/proxy/proxy_context_factory.hpp>
#include <snet/proxy/proxy_context.hpp>
#include <snet/proxy/proxy_acceptor.hpp>
#include <snet/proxy/proxy_consumer.hpp>

#include <snet/probe.hpp>
#include <snet/probe/unified_acceptor.hpp>
#include <snet/probe/unified_consumer.hpp>

#include <snet/utils/print_hex.hpp>

using namespace casket;
using namespace casket::opt;
using namespace snet::layers;
using namespace snet::tcp;
using namespace snet::proxy;
using namespace snet::probe;

namespace fs = std::filesystem;

using SessionContexts = std::tuple<TcpConnection, ProxyContext, ProbeContext>;
using SessionManager = snet::session::SessionManager<uint32_t, SessionContexts>;

class CmdLineProcessor final
{
public:
    struct Parameters
    {
        std::string configPath;
        std::string driverPath;
    };

    CmdLineProcessor()
    {
        // clang-format off
        parser_.add(
            OptionBuilder({"help", "h"})
                .setDescription("Print help message")
                .build()
        );
        parser_.add(
            OptionBuilder({"config", "c"}, Value(&args_.configPath))
                .setDescription("Path to configuration file for SNET driver")
                .setRequired()
                .build()
        );
        parser_.add(
            OptionBuilder({"driver", "d"}, Value(&args_.driverPath))
                .setDescription("Path to loadable SNET driver")
                .setRequired()
                .build()
        );
        // clang-format on
    }

    CmdLineOptionsParser& getParser() noexcept
    {
        return parser_;
    }

    const Parameters& getParameters() const noexcept
    {
        return args_;
    }

private:
    CmdLineOptionsParser parser_;
    Parameters args_;
};

enum class LoopAction
{
    Continue,
    StopOk,
    StopError
};

LoopAction handleStatus(RecvStatus st, bool stopRequested)
{
    switch (st)
    {
    case RecvStatus::Ok:
    case RecvStatus::Timeout:
    case RecvStatus::WouldBlock:
    case RecvStatus::NoBuffer:
        return stopRequested ? LoopAction::StopOk : LoopAction::Continue;

    case RecvStatus::Interrupted:
        return LoopAction::StopOk;

    case RecvStatus::Eof:
        return LoopAction::StopOk;

    case RecvStatus::NoMemory:
    case RecvStatus::Error:
        return LoopAction::StopError;
    }
    return LoopAction::StopError;
}

int main(int argc, char* argv[])
{
    LogWorker logWorker(std::make_unique<ConsoleSink>());
    int ret{EXIT_SUCCESS};

    try
    {
        std::vector<nonstd::string_view> args(argv + 1, argv + argc);
        CmdLineProcessor cli;

        cli.getParser().parse(args);
        if (cli.getParser().isUsed("help"))
        {
            cli.getParser().help(std::cout, argv[0]);
            logWorker.stop();
            return EXIT_SUCCESS;
        }

        cli.getParser().validate();
        const auto& params = cli.getParameters();

        AsyncLogger::getInstance().setLevel(LogLevel::DEBUG);

        casket::opt::ConfigOptions options;
        snet::io::Controller controller(options);
        SessionManager mgr;

        snet::io::DriverSpec driverSpec;
        driverSpec.setPath(params.driverPath);
        driverSpec.setLogger(&AsyncLogger::getInstance());

        auto driver = controller.load(driverSpec);

        casket::opt::ConfigOptionsReader reader;
        std::ifstream ifs(params.configPath);
        if (!ifs)
        {
            throw std::system_error(errno, std::system_category(), "failed to open config file: " + params.configPath);
        }
        reader.read(ifs, options);

        controller.configure(driver->getName());

        snet::io::PacketPoolInfo info;
        auto status = driver->getMsgPoolInfo(info);
        if (status == Status::Success)
        {
            std::cout << info << std::endl;
        }

        casket::SignalHandler sigHandler;
        std::atomic<bool> g_stop{false};

        snet::io::DriverGuard guard(driver.get());

        int sigs[] = {SIGINT, SIGTERM};
        std::error_code ec;
        sigHandler.registerSignals(
            sigs,
            [&](int /*signum*/)
            {
                g_stop.store(true, std::memory_order_relaxed);
                guard.interrupt();
            },
            ec);
        if (ec)
            throw std::system_error(ec);

        driver->start();
        std::cout << "listening... (Ctrl+C to stop)\n";
        snet::arp::ArpTransport arpTransport(*driver);
        snet::arp::ArpResolver arpResolver(arpTransport);
        auto networkSink = std::make_unique<NetworkSink>(*driver, arpResolver);

        auto* d0 = driver->deviceAt(0);
        auto ip0 = snet::layers::IPv4Address::fromString("10.0.0.254").value();
        arpResolver.addLocal(d0->id(), ip0, d0->mac());

        auto* d1 = driver->deviceAt(1);
        auto ip1 = snet::layers::IPv4Address::fromString("10.0.1.254").value();
        arpResolver.addLocal(d1->id(), ip1, d1->mac());

        networkSink->addSubnet(
            d0->id(), IPv4Address::fromString("10.0.0.0").value(), IPv4Address::fromString("255.255.255.0").value());

        networkSink->addSubnet(
            d1->id(), IPv4Address::fromString("10.0.1.0").value(), IPv4Address::fromString("255.255.255.0").value());

        auto routing = std::make_unique<snet::pp::RoutingStage>();
        if (driver->deviceCount() >= 2)
        {
            routing->setPeer(d0->id(), d1->id());
            routing->setLocal(d0->id(), ip0);
            routing->setLocal(d1->id(), ip1);
        }

        /**
         * Pools initialization.
         */
        auto rxPool = std::make_unique<RxRingPool>(1024);
        auto txPool = std::make_unique<TxRingPool>(1024);

        auto fRegistry = std::make_unique<SessionManager::FactoryRegistry>();
        fRegistry->addFactory<TcpConnectionCtxFactory<SessionManager>>(rxPool.get(), txPool.get());
        fRegistry->addFactory<ProxyContextFactory<SessionManager>>();
        fRegistry->addFactory<ProbeContextFactory<SessionManager>>();
        mgr.setFactoryRegistry(std::move(fRegistry));

        /**
         * TX handler for session initialization.
         */
        TcpTransmitHandlerConfig txCfg;
        txCfg.packetHeadroom = 14;
        txCfg.maxPacketSize = 65536;
        txCfg.ttl = 64;

        auto sessionTx = std::make_shared<TcpTransmitHandler<SessionManager>>(networkSink.get(), txCfg);
        
        /**
         * Probe connection initialization.
         */
        snet::proxy::DecisionCache cache{snet::proxy::DecisionCache::Config{}};
        auto policy = [](std::string_view sni,
                         const snet::proxy::CertificateChain& chain) -> snet::proxy::InspectionDecision
        {
            (void)sni;
            (void)chain;
            return snet::proxy::InspectionDecision::Bypass;
        };

        ProbeConnector<SessionManager> connector(mgr, *sessionTx.get());
        ProbeClient<SessionManager> probeClient(connector, ip1);
        snet::proxy::TlsDecisionEngine engine{probeClient, cache, policy};

        /**
         * RX handler for session initialization.
         */
        
        auto clientAcceptor = std::make_shared<ProxyAcceptor<SessionManager>>(&mgr, sessionTx.get(), ip1);
        auto clientConsumer = std::make_shared<ProxyConsumer<SessionManager>>(
            &mgr, sessionTx.get(), &engine, clientAcceptor.get());

        ProbeAcceptorConfig accCfg;
        accCfg.preferredVersion = snet::tls::ProtocolVersion::TLSv1_2;
        auto probeAcceptor = std::make_shared<ProbeAcceptor<SessionManager>>(mgr, *sessionTx, accCfg);
        auto probeConsumer = std::make_shared<ProbeStreamConsumer<SessionManager>>(mgr);

        auto unifiedAcceptor = std::make_shared<UnifiedAcceptor<SessionManager>>(mgr, *clientAcceptor, *probeAcceptor);
        auto unifiedConsumer = std::make_shared<UnifiedConsumer<SessionManager>>(mgr, *clientConsumer, *probeConsumer);

        auto sessionRx = std::make_shared<snet::tcp::TcpReceiveHandler<SessionManager>>(unifiedAcceptor.get(),
                                                                                        unifiedConsumer.get());

        /**
         * Session pipeline initialization.
         */
        auto sessionPipeline = std::make_unique<SessionManager::Pipeline>();
        sessionPipeline->add(sessionRx);
        sessionPipeline->add(sessionTx);
        mgr.setPipeline(std::move(sessionPipeline));

        /**
         * Packet pipeline initialization.
         */
        snet::pp::PacketPipeline packetPipeline;

        packetPipeline.addStage(std::make_unique<snet::pp::L2FilterStage>(*driver));
        packetPipeline.addStage(std::make_unique<snet::pp::ArpInterceptorStage>(arpResolver));
        packetPipeline.addStage(std::move(routing));
        packetPipeline.addStage(std::make_unique<snet::pp::IpForwardStage>());
        packetPipeline.addStage(std::make_unique<snet::pp::SessionStage<SessionManager>>(mgr));
        packetPipeline.addStage(std::make_unique<snet::pp::ForwardingStage>(*driver, arpResolver));

        constexpr uint16_t batchSize = 32;
        snet::io::Driver::RxItem rx[batchSize];
        uint16_t received = 0;
        RecvStatus recvStatus = RecvStatus::Ok;
        std::uint64_t total = 0;

        while (!g_stop.load(std::memory_order_relaxed))
        {
            sigHandler.processSignals(ec);
            if (ec)
            {
                std::cerr << "signal handling error: " << ec.message() << '\n';
                break;
            }

            received = 0;
            recvStatus = driver->receivePackets(rx, &received, batchSize);

            for (uint16_t i = 0; i < received; ++i)
            {
                std::cout << "Ingress:" << rx[i].ingress << std::endl;
                std::cout << *rx[i].packet << std::endl;
                auto v = packetPipeline.onPacket(rx[i].packet, rx[i].ingress);
                switch (v)
                {
                case snet::pp::PacketVerdict::Pass:
                    driver->finalizePacket(rx[i].packet, Verdict::Pass);
                    break;
                case snet::pp::PacketVerdict::Drop:
                case snet::pp::PacketVerdict::Consumed:
                    driver->finalizePacket(rx[i].packet, Verdict::Block);
                    break;
                case snet::pp::PacketVerdict::Pending:
                    break;
                }
            }

            packetPipeline.onTick(
                [&](snet::layers::Packet* packet, snet::pp::PacketContext& ctx, bool ok)
                {
                    if (ok && ctx.egress != snet::io::kInvalidDevice)
                    {
                        driver->transmitPacket(packet, ctx.egress);
                    }
                    driver->finalizePacket(packet, ok ? Verdict::Pass : Verdict::Block);
                });

            const bool stopReq = g_stop.load(std::memory_order_relaxed);
            switch (handleStatus(recvStatus, stopReq))
            {
            case LoopAction::Continue:
                if (recvStatus == RecvStatus::NoBuffer || recvStatus == RecvStatus::WouldBlock)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
                continue;

            case LoopAction::StopOk:
                goto done;

            case LoopAction::StopError:
                std::cerr << "driver error, last status=" << static_cast<int>(status) << '\n';
                ret = EXIT_FAILURE;
                goto done;
            }
        }

    done:
        std::cout << "\nDone. packets=" << total << ", driver status=" << static_cast<int>(recvStatus) << '\n';
    }
    catch (std::exception& e)
    {
        std::cout << "Error: " << e.what() << std::endl;
        ret = EXIT_FAILURE;
    }

    logWorker.stop();
    return ret;
}
