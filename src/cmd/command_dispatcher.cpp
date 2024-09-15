#include <stdexcept>
#include <snet/cmd/command_dispatcher.hpp>

namespace snet::cmd
{

CommandDispatcher::CommandPtr CommandDispatcher::createCommand(const std::string& name)
{
    auto command = commands_.find(name.data());
    if (command == commands_.end())
    {
        throw std::runtime_error("Unknown command: " + name);
    }
    return std::get<CommandCreator>(command->second)();
}

void CommandDispatcher::printCommands(std::ostream& os)
{
    for(auto [name, meta] : commands_)
    {
        os << name << "        " << std::get<CommandDescription>(meta) << std::endl;
    }
    os << std::endl;
}

CommandDispatcher::CommandMap& CommandDispatcher::getCommands()
{
    return commands_;
}

CommandDispatcher::Registrar::Registrar(
    const std::string& name, const std::string& desc, const CommandDispatcher::CommandCreator& creator)
{
    auto& commands = CommandDispatcher::Instance().getCommands();
    if (commands.find(name) != commands.end())
    {
        throw std::logic_error("Duplicated command: " + name);
    }

    commands.insert(std::make_pair(name, std::make_tuple(desc, creator)));
}

} // namespace snet