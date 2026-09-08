#include <iostream>
#include <casket/opt/opt.hpp>
#include <casket/utils/hexlify.hpp>
#include <casket/utils/error_code.hpp>

#include <casket/opt/opt.hpp>
#include <casket/log/log.hpp>

#include <snet/utils/print_hex.hpp>
#include <snet/cli/command_dispatcher.hpp>

#include <snet/layers.hpp>
#include <snet/io.hpp>

#include <snet/utils/print_hex.hpp>

using namespace snet;
using namespace casket;
using namespace casket::opt;

struct Spoofy
{
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> plaintext;
};

using SessionManager = std::unordered_map<uint32_t, std::shared_ptr<Spoofy>>;

void tcpReassemblyMsgReadyCallback(const int8_t sideIndex, const layers::TcpStreamData& tcpData,
                                   void* userCookie)
{
    auto manager = static_cast<SessionManager*>(userCookie);
    (void)sideIndex;
    if (tcpData.getMissingByteCount() == 0)
    {
        auto flowKey = tcpData.getConnectionData().getFlowKey();
        auto session = manager->find(flowKey);
        if (session == manager->end())
        {
            auto result = manager->emplace(std::make_pair(flowKey, std::make_shared<Spoofy>()));
            if (result.second)
            {
                session = result.first;
            }
        }
    }
}


class CmdLineProcessor final
{
public:
    struct Parameters
    {
        std::string configPath;
        std::string input;
        std::string driverPath;
    };

    CmdLineProcessor()
    {
        // clang-format off
        parser_.add(
            OptionBuilder("help")
                .setDescription("Print help message")
                .build()
        );
        parser_.add(
            OptionBuilder("config", Value(&args_.configPath))
                .setDescription("Path to configuration file")
                .build()
        );
        parser_.add(
            OptionBuilder("no-stats")
                .setDescription("Disable statistics collection")
                .build()
        );
        parser_.add(
            OptionBuilder("input", Value(&args_.input))
                .setDescription("Input PCAP file")
                .build()
        );
        parser_.add(
            OptionBuilder("driver", Value(&args_.driverPath))
                .setDescription("Driver path")
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
            return EXIT_SUCCESS;
        }

        cli.getParser().validate();
        const auto& params = cli.getParameters();

        AsyncLogger::getInstance().setLevel(LogLevel::DEBUG);

        SessionManager manager;

        io::Config config;
        config.setInput(params.input);
        config.setMsgPoolSize(128);
        config.setTimeout(0);
        config.setSnaplen(2048);
        config.setMode(Mode::Inline);
        
        io::DriverConfig drv;
        drv.setPath(params.driverPath);

        io::Controller controller;
        auto driver = controller.load(drv);

        layers::TcpReassemblyCallbacks callbacks;
        callbacks.onMessageReady = tcpReassemblyMsgReadyCallback;

        layers::TcpReassembly tcpReassembly(callbacks, &manager);
        driver->configure(config);

        driver->start();

        size_t numOfConnectionsProcessed = tcpReassembly.getConnectionInformation().size();

        tcpReassembly.closeAllConnections();
        driver->stop();

        logWorker.stop();

        std::cout << "Done! processed " << numOfConnectionsProcessed << " connections" << std::endl;

    }
    catch (std::exception& e)
    {
        std::cout << "Error: " << e.what() << std::endl;
        ret = EXIT_FAILURE;
    }

    logWorker.stop();
    return ret;
}
