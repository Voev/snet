#include <iostream>

#include <snet/pki/pki_manager.hpp>

#include <casket/transport/unix_socket.hpp>
#include <casket/server/generic_server.hpp>
#include <casket/signal/signal_handler.hpp>

#include <casket/opt/opt.hpp>
#include <casket/log/log.hpp>

#include "config/config_manager.hpp"

using namespace casket;
using namespace casket::opt;
using namespace snet;
using namespace snet::crypto;

namespace fs = std::filesystem;

class CmdLineProcessor final
{
public:
    struct Parameters
    {
        std::string configPath;
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

std::string getDefaultConfigPath()
{
    const char* home = std::getenv("HOME");
    if (home == nullptr)
    {
        throw std::runtime_error("HOME environment variable is not set");
    }
    
    fs::path configPath = fs::path(home) / ".snet";
    return configPath.string();
}

int main(int argc, char* argv[])
{
    LogWorker logWorker(std::make_unique<ConsoleSink>());
    int ret{EXIT_SUCCESS};

    try
    {
        std::vector<nonstd::string_view> args(argv + 1, argv + argc);
        CmdLineProcessor cli;
        bool disableStats{false};

        cli.getParser().parse(args);
        if (cli.getParser().isUsed("help"))
        {
            cli.getParser().help(std::cout, argv[0]);
            return EXIT_SUCCESS;
        }

        cli.getParser().validate();
        const auto& params = cli.getParameters();
        disableStats = cli.getParser().isUsed("no-stats");

        std::string configPath = params.configPath;
        if (configPath.empty())
        {
            configPath = getDefaultConfigPath();
        }

        ConfigManager config;
        config.initialize(configPath);

        AsyncLogger::getInstance().setLevel(LogLevel::DEBUG);

        SignalHandler signalHandler;

        std::atomic_bool interrupted{false};
        int signals[] = {SIGINT, SIGTERM};

        signalHandler.registerSignals(signals,
                                      [&interrupted](int signum)
                                      {
                                          std::cout << "\nReceived signal " << signum << " (SIGINT), shutting down..."
                                                    << std::endl;
                                          interrupted = true;
                                      });

        pki::PKIManager proc(*config.storage());

        GenericServerConfig conf;
        conf.idleTimeout = std::chrono::seconds(300);
        GenericServer<UnixSocket> server(conf);

        server.setConnectionHandler(
            [&proc](Context<UnixSocket>& ctx)
            {
                if (!proc.processCommand(ctx))
                {
                    std::cerr << "Internal error" << std::endl;
                }
            });

        server.setErrorHandler([](const std::error_code& ec)
                               { std::cerr << "Server error: " << ec.message() << std::endl; });

        std::error_code ec{};

        if (!server.listen(config.generic()->socketName, -1, 128, ec))
        {
            std::cerr << "Failed to listen on " << config.generic()->socketName << ", error: " << ec.message()
                      << std::endl;
            return false;
        }

        server.start();

        while (!interrupted)
        {
            if (!server.step())
            {
                break;
            }

            signalHandler.processSignals(ec);
            if (ec)
            {
                std::cerr << "Error processing signals: " << ec.message() << std::endl;
            }

            if (!disableStats)
            {
                enablePeriodicStats(server, std::chrono::seconds(3), std::cout);
            }
        }

        server.stop();
    }
    catch (std::exception& e)
    {
        std::cout << "Error: " << e.what() << std::endl;
        ret = EXIT_FAILURE;
    }

    logWorker.stop();
    return ret;
}
