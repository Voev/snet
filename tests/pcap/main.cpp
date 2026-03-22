#include <gtest/gtest.h>
#include <snet/config_parser/config_parser.hpp>
#include <casket/log/log_manager.hpp>
#include <casket/utils/string.hpp>
#include "controller_manager.hpp"

using namespace casket;

static inline Level ParseLogLevel(std::string_view str)
{
    if (::iequals(str, "alert"))
    {
        return Level::Alert;
    }
    else if (::iequals(str, "crit"))
    {
        return Level::Critical;
    }
    else if (::iequals(str, "error"))
    {
        return Level::Error;
    }
    else if (::iequals(str, "warn"))
    {
        return Level::Warning;
    }
    else if (::iequals(str, "notice"))
    {
        return Level::Notice;
    }
    else if (::iequals(str, "info"))
    {
        return Level::Info;
    }
    else if (::iequals(str, "debug"))
    {
        return Level::Debug;
    }

    return Level::Emergency;
}

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
        else if (arg == "--driver")
        {
            if (i + 1 < argc)
            {
                snet::io::DriverConfig config;
                config.setPath(argv[++i]);
                snet::ControllerManager::Instance().loadDriver(config);
            }
            else
            {
                throw std::runtime_error("Error: Missing value for " + std::string(arg));
            }
        }
        else if (arg == "--log-level")
        {
            if (i + 1 < argc)
            {
                LogManager::Instance().enable(Type::Console);
                LogManager::Instance().setLevel(ParseLogLevel(argv[++i]));
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