#include <chrono>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <snet/log/console.hpp>
#include <snet/log/color.hpp>

namespace
{

std::string currentTimeAndDate()
{
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "[%X %Y-%m-%d]");
    return ss.str();
}

void cerr(std::string_view color, std::string_view label, std::string_view msg)
{
    std::cerr << currentTimeAndDate() << "[" << color << label
              << snet::log::resetColor << "] " << msg << std::endl;
}

void cout(std::string_view color, std::string_view label, std::string_view msg)
{
    std::cout << currentTimeAndDate() << "[" << color << label
              << snet::log::resetColor << "] " << msg << std::endl;
}

} // namespace

namespace snet::log
{
void Console::emergency(std::string_view msg)
{
    cerr(bRed, "EMERG", msg);
}

void Console::alert(std::string_view msg)
{
    cerr(bRed, "ALERT", msg);
}

void Console::critical(std::string_view msg)
{
    cerr(bRed, "CRITL", msg);
}

void Console::error(std::string_view msg)
{
    cerr(bRed, "ERROR", msg);
}

void Console::warning(std::string_view msg)
{
    cout(bYellow, "WARNG", msg);
}

void Console::notice(std::string_view msg)
{
    cout(bWhite, "NOTIC", msg);
}

void Console::info(std::string_view msg)
{
    cout(bWhite, "INFOR", msg);
}

void Console::debug(std::string_view msg)
{
    cout(bCyan, "DEBUG", msg);
}

} // namespace snet::log