#include <snet/command.hpp>
#include <snet/command_dispatcher.hpp>
#include <snet/utils/options_parser.hpp>
#include <snet/event/watcher.hpp>
#include <snet/event/context.hpp>
#include <snet/network/socket.hpp>
#include <snet/network/tcp.hpp>
#include <snet/log/logger.hpp>

namespace snet
{

struct Options
{
    std::string address;
    std::uint16_t port{0};
    std::size_t clientCount{1};
};


class ClientCommand final : public Command
{
public:
    ClientCommand()
    {
        parser_.add("help, h", "Print help message");
        parser_.add("ip, i", utils::Value(&options_.address),
                    "Target IP address");
        parser_.add("port, p", utils::Value(&options_.port), "Target port");
    }

    ~ClientCommand() = default;

    std::string_view description() const override
    {
        return "client impl";
    }

    void execute(const std::vector<std::string>& args) override
    {
        parser_.parse(args);

        if (parser_.isUsed("help"))
        {
            parser_.help(std::cout, "snet client");
            return;
        }

        network::Socket<network::Tcp> sock;

        sock.open(network::Tcp::v4());
        auto ip = network::IPAddress::fromString(options_.address.c_str());
        network::Endpoint target(ip.value(), options_.port);

        std::error_code ec;
        sock.connect(target, ec);

        if(ec)
            log::error(ec.message());
        else 
            log::info("success");
    }

private:
    utils::OptionsParser parser_;
    Options options_;
};

REGISTER_COMMAND("client", ClientCommand);

} // namespace snet
