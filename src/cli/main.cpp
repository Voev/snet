#include <iostream>
#include <casket/utils/string.hpp>
#include <snet/cli/command_dispatcher.hpp>

using namespace casket::utils;
using namespace snet::cmd;

int main(int argc, char* argv[])
{
    try
    {
        std::vector<std::string_view> args(argv + 1, argv + argc);

        if (args.empty())
        {
            std::cerr << "Use '--help' to print commands" << std::endl;
            return EXIT_SUCCESS;
        }
        else if (equals(args.front(), "-h") || equals(args.front(), "--help"))
        {
            CommandDispatcher::Instance().printCommands(std::cout);
            return EXIT_SUCCESS;
        }

        auto cmd = CommandDispatcher::Instance().createCommand(argv[1]);
        args.erase(args.begin());
        cmd->execute(args);
    }
    catch (const std::system_error& e)
    {
        std::cerr << e.what() << "[" << e.code() << "]" << std::endl;
        return EXIT_FAILURE;
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}