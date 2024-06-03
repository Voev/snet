#include <iostream>
#include <snet/command_dispatcher.hpp>

int main(int argc, char* argv[])
{
    try
    {
        /* code */

        if (argc < 2)
        {
            throw std::runtime_error(
                "unknown command, use --help to display help info");
        }
        std::string_view command(argv[1]);

        auto cmd = snet::CommandDispatcher::getCommand(command);
        if(!cmd)
        {
            throw std::runtime_error("unknown command");
        }

        std::vector<std::string> args(argv + 2, argv + argc);
        cmd->execute(args);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}