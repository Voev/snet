#include <iostream>

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

#include <snet/iface_utils.hpp>

using namespace casket;
using namespace casket::opt;

namespace fs = std::filesystem;

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

        auto arpTransport = std::make_unique<snet::arp::ArpTransport>(*driver);
        snet::arp::ArpResolver arpResolver(*arpTransport);

        auto* d0 = driver->deviceAt(0);
        auto ip0 = snet::layers::IPv4Address::fromString("10.0.0.2").value();
        arpResolver.addLocal(d0->id(), ip0, d0->mac());

        auto* d1 = driver->deviceAt(1);
        auto ip1 = snet::layers::IPv4Address::fromString("10.0.0.1").value();
        arpResolver.addLocal(d1->id(), ip1, d1->mac());

        snet::pp::PacketPipeline pipeline;

        pipeline.addStage(std::make_unique<snet::pp::L2FilterStage>(*driver));
        pipeline.addStage(std::make_unique<snet::pp::ArpInterceptorStage>(arpResolver));

        auto routing = std::make_unique<snet::pp::RoutingStage>();
        if (driver->deviceCount() >= 2)
        {
            routing->setPeer(d0->id(), d1->id());
        }
        pipeline.addStage(std::move(routing));
        pipeline.addStage(std::make_unique<snet::pp::IpForwardStage>());
        // pipeline.addStage(std::make_unique<snet::pp::SessionStage<SessionManager>>(sessionManager));
        pipeline.addStage(std::make_unique<snet::pp::ForwardingStage>(*driver, arpResolver));

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
                auto v = pipeline.onPacket(rx[i].packet, rx[i].ingress);
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

            pipeline.onTick(
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
