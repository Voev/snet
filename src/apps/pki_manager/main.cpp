#include <iostream>

#include <snet/pki/cert_manager.hpp>
#include "message.hpp"

#include <atomic>

#include <casket/transport/unix_socket.hpp>
#include <casket/server/generic_server.hpp>
#include <casket/signal/signal_handler.hpp>

#include <casket/opt/cmd_line_options_parser.hpp>
#include <casket/opt/option_builder.hpp>
#include <casket/opt/option_value_handler.hpp>

using namespace casket;
using namespace casket::opt;
using namespace snet;
using namespace snet::crypto;

class CmdLineProcessor final
{
public:
    struct Parameters
    {
        std::string address;
        std::string dbPath;
        size_t fsBlockSize{0};
        size_t maxDbSize{0};
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
            OptionBuilder("address", Value(&args_.address))
                .setDescription("Listening address")
                .build()
        );       
        parser_.add(
            OptionBuilder("create-db")
                .setDescription("Init database directory and exit")
                .build()
        );        
        parser_.add(
            OptionBuilder("db-path", Value(&args_.dbPath))
                .setDescription("Directory path of SSL storage database")
                .build()
        );        
        parser_.add(
            OptionBuilder("max-db-size", Value(&args_.maxDbSize))
                .setDescription("Maximum size of disk storage")
                .build()
        );        
        parser_.add(
            OptionBuilder("fs-block-size", Value(&args_.fsBlockSize))
                .setDescription("File system block size in bytes")
                .setDefaultValue(2048)
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
    try
    {
        std::vector<std::string_view> args(argv + 1, argv + argc);
        CmdLineProcessor cli;

        cli.getParser().parse(args);
        if (cli.getParser().isUsed("help"))
        {
            cli.getParser().help(std::cout, argv[0]);
            return EXIT_SUCCESS;
        }

        cli.getParser().validate();
        const auto& params = cli.getParameters();

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

        CertificateManager proc(params.dbPath);

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

        if (!server.listen(params.address, -1, 128, ec))
        {
            std::cerr << "Failed to listen on " << params.address << ", error: " << ec.message() << std::endl;
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

            enablePeriodicStats(server, std::chrono::seconds(3), std::cout);
        }

        server.stop();
    }
    catch (std::exception& e)
    {
        std::cout << "Error: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
