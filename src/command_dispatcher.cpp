#include <snet/command_dispatcher.hpp>
#include <snet/utils/format.hpp>
#include <stdexcept>

namespace snet
{

std::unique_ptr<Command> CommandDispatcher::getCommand(std::string_view name)
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
    std::string_view name, const CommandDispatcher::CommandCreator& creator)
{
    auto& map = CommandDispatcher::getCommandMap();
    if (map.find(name) != map.end())
    {
        throw std::logic_error(utils::Format("duplicated command '{}'", name));
    }

    map.insert(std::make_pair(name, creator));
}

} // namespace snet