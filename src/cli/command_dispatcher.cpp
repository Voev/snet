#include <stdexcept>
#include <sstream>
#include <algorithm>
#include <snet/cli/command_dispatcher.hpp>

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
    auto maxElement = std::max_element(
        commands_.begin(), commands_.end(),
        [](const auto& lhs, const auto& rhs) {
            return lhs.first.size() < rhs.first.size();
        }
    );

    const auto offset = (maxElement != commands_.end()) ? maxElement->first.size() + 4 : 4;

    for(auto [name, meta] : commands_)
    {
        os << name;

        const std::size_t padding = offset - name.size();
        os << std::string(padding, ' ');

        os << std::get<CommandDescription>(meta) << std::endl;
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