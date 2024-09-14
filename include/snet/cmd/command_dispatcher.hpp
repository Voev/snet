#pragma once
#include <map>
#include <memory>
#include <functional>
#include <snet/cmd/command.hpp>
#include <snet/utils/noncopyable.hpp>

namespace snet::cmd
{

class CommandDispatcher final : public utils::NonCopyable
{
public:
    CommandDispatcher() = default;
    ~CommandDispatcher() = default;

    static std::unique_ptr<Command> getCommand(std::string_view name);

private:
    typedef std::function<std::unique_ptr<Command>()> CommandCreator;
    typedef std::map<std::string_view, CommandCreator> CommandMap;

    static CommandMap& getCommandMap();
public:
    class Registration final
    {
    public:
        Registration(std::string_view name, const CommandCreator& creator);
        ~Registration() = default;
    };
};

#define REGISTER_COMMAND(commandName, className)                               \
    const snet::CommandDispatcher::Registration gCommand##className(           \
        commandName, []() -> std::unique_ptr<snet::Command> {                  \
            return std::make_unique<className>();                              \
        })

} // namespace snet