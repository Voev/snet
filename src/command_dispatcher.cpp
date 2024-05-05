#include <snet/command_dispatcher.hpp>
#include <stdexcept>

namespace snet
{

std::unique_ptr<Command> CommandDispatcher::createCommand(std::string_view name)
{
    const auto& map = CommandDispatcher::getCommandMap();
    auto command = map.find(name);
    if (command != map.end())
    {
        return command->second();
    }
    return nullptr;
}

CommandDispatcher::CommandMap& CommandDispatcher::getCommandMap()
{
    static CommandDispatcher::CommandMap globalCommands;
    return globalCommands;
}

CommandDispatcher::Registration::Registration(
    const std::string& name, const CommandDispatcher::CommandCreator& creator)
{
    auto& map = CommandDispatcher::getCommandMap();
    if (map.find(name) != map.end())
    {
        throw std::logic_error("Duplicated registration of command '" + name + "'");
    }
    map[name] = creator;
}

} // namespace snet