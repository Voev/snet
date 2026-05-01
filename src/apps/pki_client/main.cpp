#include <iostream>
#include <atomic>
#include <chrono>
#include <thread>
#include <iomanip>
#include <sstream>
#include <vector>
#include <algorithm>
#include <string>
#include <utility>

#include <casket/client/generic_client.hpp>
#include <casket/opt/opt.hpp>
#include <casket/utils/timer.hpp>

#include <snet/pki/cert_manager.hpp>

using namespace snet;
using namespace casket;
using namespace casket::opt;

inline std::pair<std::string, std::string> splitIntoTwo(const std::string& str)
{
    // Trim leading/trailing spaces
    size_t start = str.find_first_not_of(" \t\n\r");
    if (start == std::string::npos)
    {
        return {"", ""};
    }
    
    size_t end = str.find_last_not_of(" \t\n\r");
    std::string trimmed = str.substr(start, end - start + 1);
    
    // Find first space
    size_t spacePos = trimmed.find_first_of(" \t");
    
    if (spacePos == std::string::npos)
    {
        // No arguments, just command
        return {trimmed, ""};
    }
    
    // Split into command and args
    std::string command = trimmed.substr(0, spacePos);
    std::string args = trimmed.substr(spacePos + 1);
    
    // Trim args
    size_t argsStart = args.find_first_not_of(" \t\n\r");
    if (argsStart != std::string::npos)
    {
        args = args.substr(argsStart);
    }
    
    return {command, args};
}

struct CommandOptions
{
    std::string connectAddress;
    std::chrono::milliseconds timeout{5000};
    bool interactive{false};
    bool verbose{false};
};

class CertManagerInterpreter
{
public:
    CertManagerInterpreter()
    {
        // clang-format off
        parser_.add(
            OptionBuilder("help")
                .setDescription("Print help message")
                .build()
        );
        parser_.add(
            OptionBuilder("connect", Value(&options_.connectAddress))
                .setDescription("Connection address")
                .setDefaultValue("/tmp/cert_siner")
                .build()
        );
        parser_.add(
            OptionBuilder("timeout", Value(&options_.timeout))
                .setDescription("Request timeout (ms)")
                .setDefaultValue(5000)
                .build()
        );
        parser_.add(
            OptionBuilder("interactive")
                .setDescription("Run in interactive mode")
                .build()
        );
        parser_.add(
            OptionBuilder("async")
                .setDescription("Asynchronous connection mode")
                .build()
        );
        parser_.add(
            OptionBuilder("verbose")
                .setDescription("Verbose output")
                .build()
        );
        parser_.add(
            OptionBuilder("command", Value(&singleCommand_))
                .setDescription("Execute single command and exit")
                .build()
        );
        // clang-format on
    }

    int run(int argc, char* argv[])
    {
        parser_.parse(argc, argv);

        if (parser_.isUsed("help"))
        {
            printHelp(argv[0]);
            return EXIT_SUCCESS;
        }

        parser_.validate();

        options_.interactive = parser_.isUsed("interactive");
        options_.verbose = parser_.isUsed("verbose");

        // Connect to server
        if (!connectToServer())
        {
            return EXIT_FAILURE;
        }

        // Execute single command if provided
        if (!singleCommand_.empty())
        {
            return executeCommand(singleCommand_) ? EXIT_SUCCESS : EXIT_FAILURE;
        }

        // Interactive mode
        if (options_.interactive)
        {
            return interactiveMode();
        }

        // No command specified
        std::cerr << "No command specified. Use --command or --interactive mode." << std::endl;
        printHelp(argv[0]);
        return EXIT_FAILURE;
    }

private:
    bool connectToServer()
    {
        std::error_code ec;

        std::cout << "Connecting to " << options_.connectAddress << "..." << std::endl;

        if (!client_.connect(options_.connectAddress, -1, false, ec))
        {
            std::cerr << "Failed to connect: " << ec.message() << std::endl;
            return false;
        }

        if (!client_.isConnected(options_.timeout, ec))
        {
            std::cerr << "Connection timeout: " << ec.message() << std::endl;
            return false;
        }

        std::cout << "Connected successfully!" << std::endl;
        return true;
    }

    bool executeCommand(const std::string& commandLine)
    {
        CertManagerCommand command;

        // Parse command line
        if (!parseCommand(commandLine, command))
        {
            return false;
        }

        if (options_.verbose)
        {
            printCommand(command);
        }

        // Send command
        std::error_code ec;
        Timer timer;
        timer.start();

        if (!client_.send(command, ec))
        {
            std::cerr << "Failed to send command: " << ec.message() << std::endl;
            return false;
        }

        // Receive response
        auto response = client_.receive<CertManagerResponse>(ec);
        timer.stop();

        if (!response)
        {
            std::cerr << "Failed to receive response: " << ec.message() << std::endl;
            return false;
        }

        // Print response
        printResponse(*response, timer.elapsedMicroSecs());

        return true;
    }

    bool parseCommand(const std::string& cmdLine, CertManagerCommand& command)
    {
        auto result = splitIntoTwo(cmdLine);
        command.command = std::move(result.first);
        command.args = std::move(result.second);
        return true;
    }

    void printCommand(const CertManagerCommand& cmd)
    {
        std::cout << "\n[DEBUG] Sending command:" << std::endl;
        std::cout << "  Type:" << cmd.command << ":" << cmd.args;
    }

    void printResponse(const CertManagerResponse& response, int64_t latency)
    {
        std::cout << "\n[Response] (latency: " << latency << " mcs)" << std::endl;

        // Print status
        std::cout << "Status: ";
        std::cout << response.retcode << std::endl;
    }

    int interactiveMode()
    {
        std::string commandLine;

        while (true)
        {
            std::cout << "\n> ";
            std::getline(std::cin, commandLine);

            // Trim whitespace
            commandLine.erase(0, commandLine.find_first_not_of(" \t\n\r"));
            commandLine.erase(commandLine.find_last_not_of(" \t\n\r") + 1);

            if (commandLine.empty())
            {
                continue;
            }

            std::string cmd = commandLine;
            std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::toupper);
            if (cmd == "Q")
            {
                std::cout << "Goodbye!" << std::endl;
                break;
            }

            // Execute command
            if (!executeCommand(commandLine))
            {
                if (options_.verbose)
                {
                    std::cerr << "Command execution failed" << std::endl;
                }
            }
        }

        return EXIT_SUCCESS;
    }

    void printHelp(const char* programName)
    {
        std::cout << "Usage: " << programName << " [options] [--command <cmd>]" << std::endl;
        std::cout << "\nOptions:" << std::endl;
        std::cout << "  --connect <address>     Connection address (default: /tmp/cert_siner)" << std::endl;
        std::cout << "  --timeout <ms>          Request timeout in milliseconds (default: 5000)" << std::endl;
        std::cout << "  --interactive           Run in interactive mode" << std::endl;
        std::cout << "  --command <cmd>         Execute single command and exit" << std::endl;
        std::cout << "  --async                 Use asynchronous connection mode" << std::endl;
        std::cout << "  --verbose               Enable verbose output" << std::endl;
        std::cout << "  --help                  Show this help message" << std::endl;
    }

private:
    opt::CmdLineOptionsParser parser_;
    CommandOptions options_;
    GenericClient<UnixSocket> client_;
    std::string singleCommand_;
};

int main(int argc, char* argv[])
{
    int ret{EXIT_SUCCESS};
    try
    {
        CertManagerInterpreter interpreter;
        ret = interpreter.run(argc, argv);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        ret = EXIT_FAILURE;
    }
    return ret;
}