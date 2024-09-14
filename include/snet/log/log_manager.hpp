#pragma once
#include <algorithm>
#include <map>
#include <memory>
#include <sstream>

#include <snet/log/logger.hpp>
#include <snet/log/console.hpp>
#include <snet/utils/singleton.hpp>
#include <snet/utils/format.hpp>

namespace snet::log
{

enum class Level
{
    Emergency,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Info,
    Debug
};

enum class Type
{
    Console
};

class LogManager final : public utils::Singleton<LogManager>
{
public:
    LogManager();

    ~LogManager() noexcept;

    void finalize();

    void setLevel(Level level);

    Level getLevel() const;

    void enable(Type type);

    void disable(Type type);

    template <typename... Args>
    friend void emergency(std::string_view str, Args&&... args);

    template <typename... Args>
    friend void alert(std::string_view str, Args&&... args);

    template <typename... Args>
    friend void critical(std::string_view str, Args&&... args);

    template <typename... Args>
    friend void error(std::string_view str, Args&&... args);

    template <typename... Args>
    friend void warning(std::string_view str, Args&&... args);

    template <typename... Args>
    friend void notice(std::string_view str, Args&&... args);

    template <typename... Args>
    friend void info(std::string_view str, Args&&... args);

    template <typename... Args>
    friend void debug(std::string_view str, Args&&... args);

private:
    Level maxLevel_;
    std::map<Type, std::shared_ptr<Logger>> loggers_;
};

template <typename... Args> void emergency(std::string_view str, Args&&... args)
{
    auto& inst = LogManager::Instance();
    if (Level::Emergency <= inst.getLevel())
    {
        auto msg = utils::format(str, std::forward<Args>(args)...);
        std::for_each(inst.loggers_.begin(), inst.loggers_.end(),
                      [&](const auto& l) { l.second->emergency(msg); });
    }
}

template <typename... Args> void alert(std::string_view str, Args&&... args)
{
    auto& inst = LogManager::Instance();
    if (Level::Alert <= inst.getLevel())
    {
        auto msg = utils::format(str, std::forward<Args>(args)...);
        std::for_each(inst.loggers_.begin(), inst.loggers_.end(),
                      [&](const auto& l) { l.second->alert(msg); });
    }
}

template <typename... Args> void critical(std::string_view str, Args&&... args)
{
    auto& inst = LogManager::Instance();
    if (Level::Critical <= inst.getLevel())
    {
        auto msg = utils::format(str, std::forward<Args>(args)...);
        std::for_each(inst.loggers_.begin(), inst.loggers_.end(),
                      [&](const auto& l) { l.second->critical(msg); });
    }
}

template <typename... Args> void error(std::string_view str, Args&&... args)
{
    auto& inst = LogManager::Instance();
    if (Level::Error <= inst.getLevel())
    {
        auto msg = utils::format(str, std::forward<Args>(args)...);
        std::for_each(inst.loggers_.begin(), inst.loggers_.end(),
                      [&](const auto& l) { l.second->error(msg); });
    }
}

template <typename... Args> void warning(std::string_view str, Args&&... args)
{
    auto& inst = LogManager::Instance();
    if (Level::Warning <= inst.getLevel())
    {
        auto msg = utils::format(str, std::forward<Args>(args)...);
        std::for_each(inst.loggers_.begin(), inst.loggers_.end(),
                      [&](const auto& l) { l.second->warning(msg); });
    }
}

template <typename... Args> void notice(std::string_view str, Args&&... args)
{
    auto& inst = LogManager::Instance();
    if (Level::Notice <= inst.getLevel())
    {
        auto msg = utils::format(str, std::forward<Args>(args)...);
        std::for_each(inst.loggers_.begin(), inst.loggers_.end(),
                      [&](const auto& l) { l.second->notice(msg); });
    }
}

template <typename... Args> void info(std::string_view str, Args&&... args)
{
    auto& inst = LogManager::Instance();
    if (Level::Info <= inst.getLevel())
    {
        auto msg = utils::format(str, std::forward<Args>(args)...);
        std::for_each(inst.loggers_.begin(), inst.loggers_.end(),
                      [&](const auto& l) { l.second->info(msg); });
    }
}

template <typename... Args> void debug(std::string_view str, Args&&... args)
{
    auto& inst = LogManager::Instance();
    if (Level::Debug <= inst.getLevel())
    {
        auto msg = utils::format(str, std::forward<Args>(args)...);
        std::for_each(inst.loggers_.begin(), inst.loggers_.end(),
                      [&](const auto& l) { l.second->debug(msg); });
    }
}

} // namespace snet::log