#pragma once
#include <iostream>
#include <snet/utils/format.hpp>

namespace snet::log
{

#define COLOR_L_BLACK "\x1B[0;30m"
#define COLOR_L_RED "\x1B[0;31m"
#define COLOR_L_GREEN "\x1B[0;32m"
#define COLOR_L_ORANGE "\x1B[0;33m"
#define COLOR_L_BLUE "\x1B[0;34m"
#define COLOR_L_PURPLE "\x1B[0;35m"
#define COLOR_L_CYAN "\x1B[0;36m"
#define COLOR_L_GRAY "\x1B[0;37m"

#define COLOR_B_GRAY "\x1B[1;30m"
#define COLOR_B_RED "\x1B[1;31m"
#define COLOR_B_GREEN "\x1B[1;32m"
#define COLOR_B_YELLOW "\x1B[1;33m"
#define COLOR_B_BLUE "\x1B[1;34m"
#define COLOR_B_PURPLE "\x1B[1;35m"
#define COLOR_B_CYAN "\x1B[1;36m"
#define COLOR_B_WHITE "\x1B[1;37m"

#define COLOR_RESET "\x1B[0m"

template <class... Args>
inline void error(std::string_view format, Args... args)
{
    auto str = utils::Format(format, std::forward<Args>(args)...);
    std::cerr << "[" << COLOR_L_RED << "error" << COLOR_RESET << "] " << str
              << std::endl;
}

template <class... Args>
inline void info(std::string_view format, Args... args)
{
    auto str = utils::Format(format, std::forward<Args>(args)...);
    std::cerr << "[" << COLOR_L_CYAN << "info" << COLOR_RESET << "] " << str
              << std::endl;
}

template <class... Args>
inline void debug(std::string_view format, Args... args)
{
    auto str = utils::Format(format, std::forward<Args>(args)...);
    std::cerr << "[" << COLOR_L_GRAY << "debug" << COLOR_RESET << "] " << str
              << std::endl;
}

} // namespace snet::log