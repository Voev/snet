#include <gtest/gtest.h>
#include "config_parser.hpp"

void ParseCommandLine(int argc, char* argv[])
{
    for (int i = 1; i < argc; ++i)
    {
        std::string_view arg{argv[i]};
        if (arg == "--config")
        {
            if (i + 1 < argc)
            {
                ConfigParser::Instance().parse(argv[++i]);
            }
            else
            {
                throw std::runtime_error("Error: Missing value for " + std::string(arg));
            }
        }
    }
}

int main(int argc, char* argv[])
{
    int ret{EXIT_SUCCESS};
    try
    {
        ::ParseCommandLine(argc, argv);
        testing::InitGoogleTest(&argc, argv);
        ret = RUN_ALL_TESTS();
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << std::endl;
        ret = EXIT_FAILURE;
    }
    return ret;
}