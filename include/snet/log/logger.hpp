#pragma once
#include <string_view>

namespace snet::log
{

class Logger
{
public:
    Logger() = default;
    virtual ~Logger() = default;

    virtual void emergency(std::string_view msg) = 0;
    virtual void alert(std::string_view msg) = 0;
    virtual void critical(std::string_view msg) = 0;
    virtual void error(std::string_view msg) = 0;
    virtual void warning(std::string_view msg) = 0;
    virtual void notice(std::string_view msg) = 0;
    virtual void info(std::string_view msg) = 0;
    virtual void debug(std::string_view msg) = 0;
};

} // namespace snet::log