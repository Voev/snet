#include <snet/command.hpp>
#include <snet/command_dispatcher.hpp>
#include <snet/utils/prog_options.hpp>

namespace snet
{

class PerfCommand final : public Command
{
public:
    PerfCommand()
    {
        parser_.add_argument("help, h", "Print help message");
        parser_.add_argument("ip, i", "Target IP address");
        parser_.add_argument("port, p", "Target port");
    }

    ~PerfCommand() = default;

    std::string_view description() const override
    {
        return "my desc";
    }
    void configure(const std::vector<std::string>& args) override
    {
        parser_.parse_args(args);
        (void)args;
    }
    void execute() override
    {
    }

private:
    utils::ArgumentParser parser_;
};

REGISTER_COMMAND("perf", PerfCommand);

} // namespace snet
