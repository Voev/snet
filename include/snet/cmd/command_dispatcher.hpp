#pragma once
#include <map>
#include <memory>
#include <functional>
#include <snet/cmd/command.hpp>
#include <snet/utils/singleton.hpp>

namespace snet::cmd
{

class CommandDispatcher final : public utils::Singleton<CommandDispatcher>
{
    typedef std::unique_ptr<Command> CommandPtr;
    typedef std::string CommandDescription;
    typedef std::function<CommandPtr()> CommandCreator;
    typedef std::tuple<CommandDescription, CommandCreator> CommandMeta;
    typedef std::unordered_map<std::string, CommandMeta> CommandMap;

public:
    CommandDispatcher() = default;
    ~CommandDispatcher() = default;

    CommandPtr createCommand(const std::string& name);

    void printCommands(std::ostream& os);

private:
    CommandMap& getCommands();

public:
    class Registrar final
    {
    public:
        Registrar(const std::string& name, const std::string& desc,
                  const CommandCreator& creator);
        ~Registrar() = default;
    };

private:
    CommandMap commands_;
};

#define REGISTER_COMMAND(commandName, commandDesc, className)                  \
    const snet::cmd::CommandDispatcher::Registrar className##Registrar(        \
        commandName, commandDesc,                                              \
        []() -> std::unique_ptr<snet::cmd::Command> {                          \
            return std::make_unique<className>();                              \
        })

} // namespace snet::cmd