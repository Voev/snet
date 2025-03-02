#include <iostream>

#include <casket/opt/option_parser.hpp>
#include <casket/utils/exception.hpp>

#include <snet/cli/command_dispatcher.hpp>
#include <snet/dbus.hpp>

using namespace casket;

namespace snet
{

class IoTestCommand final : public cmd::Command
{
public:
    IoTestCommand();

    ~IoTestCommand() = default;

    void execute(const std::vector<std::string_view>& args) override;

private:
    opt::OptionParser parser_;
    std::string driverPath_;
};

REGISTER_COMMAND("iotest", "Test IO drivers", IoTestCommand);

IoTestCommand::IoTestCommand()
{
    parser_.add("help, h", "Print help message");
    parser_.add("path, p", opt::Value(&driverPath_), "Path to driver");
}

void IoTestCommand::execute(const std::vector<std::string_view>& args)
{
    parser_.parse(args);

    if (parser_.isUsed("help"))
    {
        parser_.help(std::cout);
        return;
    }

}

} // namespace snet
