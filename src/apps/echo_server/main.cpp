#include <cstdio>
#include <memory>

#include <iostream>

#include <casket/opt/opt.hpp>
#include <casket/log/log.hpp>

#include <casket/signal/signal_handler.hpp>

#include <snet/io.hpp>
#include <snet/layers.hpp>
#include <snet/session.hpp>

#include <snet/tcp/tcp_listener_handler.hpp>
#include <snet/tcp/tcp_receive_handler.hpp>
#include <snet/tcp/tcp_transmit_handler.hpp>
#include <snet/tcp/tcp_listener.hpp>

#include <snet/utils/print_hex.hpp>

#include "echo_consumer.hpp"

using namespace casket;
using namespace casket::opt;
using namespace snet::layers;
using namespace snet::tcp;
using namespace echo;

namespace fs = std::filesystem;

using SessionContexts = std::tuple<TcpConnection>;
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

        SessionManager::Config sessCfg;
        sessCfg.max_sessions = 10000;
        SessionManager mgr(sessCfg);

        snet::io::DriverSpec driverSpec;
        driverSpec.setPath(params.driverPath);
        driverSpec.setLogger(&AsyncLogger::getInstance());

        auto driver = controller.load(driverSpec);

        auto srcMac = MacAddress::parse("46:4d:4b:6e:83:12");
        auto dstMac = MacAddress::parse("7a:5b:82:12:7a:81");

        auto sink = std::make_unique<NetworkSink>(driver.get(), srcMac, dstMac);
        TcpListenerRegistry listeners;
        listeners.add(IPAddress::any(), 8080);

        auto echoConsumer = std::make_unique<EchoConsumer<SessionManager>>(&mgr);

        auto rxPool = std::make_unique<RxRingPool>(1024);
        auto txPool = std::make_unique<TxRingPool>(1024);

        auto pipeline = std::make_unique<SessionManager::Pipeline>();

        pipeline->addHandler<TcpListenerHandler<SessionManager>>(&listeners);
        pipeline->addHandler<TcpReceiveHandler<SessionManager>>(rxPool.get(), nullptr, echoConsumer.get());
        pipeline->addHandler<TcpTransmitHandler<SessionManager>>(txPool.get(), sink.get());

        mgr.setPipeline(std::move(pipeline));

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

        constexpr uint16_t batchSize = 32;
        snet::layers::Packet* packets[batchSize];
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
            recvStatus = driver->receivePackets(packets, &received, batchSize);

            for (uint16_t i = 0; i < received; ++i)
            {
                snet::layers::Packet* pkt = packets[i];
                if (!pkt)
                    continue;

                pkt->parse();
                std::cout << *pkt << std::endl;

                mgr.processPacket(pkt);

                ++total;

                (void)driver->finalizePacket(pkt, Verdict::Block);
            }

            const bool stopReq = g_stop.load(std::memory_order_relaxed);
            switch (handleStatus(recvStatus, stopReq))
            {
            case LoopAction::Continue:
                if (recvStatus == RecvStatus::NoBuffer ||  recvStatus == RecvStatus::WouldBlock)
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
