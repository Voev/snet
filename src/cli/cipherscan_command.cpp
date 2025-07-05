#include <chrono>
#include <casket/opt/option_builder.hpp>
#include <casket/opt/cmd_line_options_parser.hpp>
#include <casket/thread/pool.hpp>
#include <casket/lock_free/queue.hpp>

#include <snet/cli/command_dispatcher.hpp>
#include <snet/tls.hpp>
#include <snet/socket.hpp>

#include <snet/crypto/exception.hpp>

using namespace snet::socket;
using namespace snet::tls;

using namespace casket::opt;
using namespace casket::thread;
using namespace casket::lock_free;

using namespace std::chrono_literals;

struct Options
{
    std::string input;
    std::size_t threads{4};
};

bool Connect(const Endpoint& endpoint)
{
    try
    {
        std::error_code ec;

        auto socket = CreateSocket(endpoint.isIPv4() ? Tcp::v4() : Tcp::v6(), ec);
        casket::ThrowIfError(ec);

        SetNonBlocking(socket, true, ec);
        casket::ThrowIfError(ec);

        Connect(socket, endpoint.data(), endpoint.size(), ec);
        if (ec == std::errc::operation_in_progress)
        {
            ec.clear();
            WaitSocket(socket, false, 3s, ec);
        }
        casket::ThrowIfError(ec);
    }
    catch (const std::exception& e)
    {
        std::cerr << e.what() << '\n';
        return false;
    }
    return true;
}

void CheckCipher(const Endpoint& endpoint, std::string_view cipherSuite, Queue<std::string_view>& ret)
{
    try
    {
        ClientSettings settings;
        if (cipherSuite.find("TLS_", 0) == 0)
        {
            settings.setMaxVersion(ProtocolVersion::TLSv1_3);
            settings.setCipherSuites(cipherSuite);
        }
        else
        {
            settings.setMaxVersion(ProtocolVersion::TLSv1_2);
            settings.setCipherList(cipherSuite);
        }

        std::error_code ec;

        auto socket = CreateSocket(endpoint.isIPv4() ? Tcp::v4() : Tcp::v6(), ec);
        casket::ThrowIfError(ec);

        Connect(socket, endpoint.data(), endpoint.size(), ec);
        casket::ThrowIfError(ec);

        Connection conn = settings.createConnection();
        conn.setConnectState();
        conn.setSocket(socket);

        snet::crypto::ThrowIfFalse(0 < conn.doHandshake());
        ret.push(cipherSuite);
    }
    catch (const std::exception& e)
    {
        (void)e;
    }
}

namespace snet
{

class CipherScanCommand final : public cmd::Command
{
public:
    CipherScanCommand()
    {
        // clang-format off
        parser_.add(
            OptionBuilder("help")
                .setDescription("Print help message")
                .build()
        );
        parser_.add(
            OptionBuilder("threads", Value(&options_.threads))
                .setDescription("Number of threads")
                .build()
        );
        parser_.add(
            OptionBuilder("input", Value(&options_.input))
                .setDescription("Target remote host")
                .build()
        );
        // clang-format on
    }

    ~CipherScanCommand() = default;

    void execute(const std::vector<std::string_view>& args) override
    {
        parser_.parse(args);
        if (parser_.isUsed("help"))
        {
            parser_.help(std::cout, "snet cipherscan");
            return;
        }
        parser_.validate();

        auto cipherSuites = tls::CipherSuiteManager::getInstance().getCipherSuites();
        std::vector<std::future<void>> results;

        socket::ResolverOptions options;
        options.allowDns(true);
        options.expectPort(true);

        snet::socket::Resolver resolver;

        socket::Endpoint ep;
        bool found{false};
        for (auto it = resolver.resolve(options_.input, options); it != resolver.end(); ++it)
        {
            if (::Connect(*it))
            {
                ep = *it;
                found = true;
                break;
            }
        }
        casket::ThrowIfFalse(found, "Can't connect with endpoint");

        ThreadPool pool(options_.threads);

        Queue<std::string_view> ret;
        results.reserve(cipherSuites.size());
        for (const auto& cipherSuite : cipherSuites)
        {
            results.emplace_back(
                pool.add(&CheckCipher, ep, CipherSuiteGetName(cipherSuite), std::ref(ret)));
        }

        for (auto& result : results)
        {
            result.get();
        }
        results.clear();

        while (true)
        {
            auto cs = ret.pop();
            if (cs.has_value())
            {
                std::cout << cs.value() << std::endl;
            }
            else
            {
                break;
            }
        }
    }

private:
    CmdLineOptionsParser parser_;
    Options options_;
};

REGISTER_COMMAND("cipherscan", "Server scanner that determines supported TLS cipher suites",
                 CipherScanCommand);

} // namespace snet
