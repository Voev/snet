#include <chrono>
#include <atomic>
#include <snet/command.hpp>
#include <snet/command_dispatcher.hpp>
#include <snet/utils/options_parser.hpp>
#include <snet/tls/context.hpp>
#include <snet/tls/handle.hpp>
#include <snet/event/epoll.hpp>
#include <snet/event/service.hpp>
#include <snet/event/context.hpp>
#include <snet/event/timer.hpp>
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

std::atomic<bool> finish{false};

class SessionManager
{
private:
    friend class Session;

private:
    event::Context io_;
    std::unique_ptr<tls::ClientContext> ctx_;
    network::Endpoint target_;
    std::list<event::Service*> reconnect_q_;
    std::list<event::Service*> backlog_;

public:
    SessionManager(const network::Endpoint& target)
        : io_()
        , ctx_(std::make_unique<tls::ClientContext>())
        , target_(target)
    {
        event::Timer timer(io_);
        auto handler = [](event::Service* s, uint32_t events) {

        };
        timer.setHandler(std::move(handler));

        ctx_->setMinVersion(tls::ProtocolVersion::TLSv1_2);
        ctx_->setMaxVersion(tls::ProtocolVersion::TLSv1_3);
        ctx_->setVerifyCallback(tls::VerifyMode::None, nullptr);
    }

    ~SessionManager()
    {
        reconnect_q_.clear();
    }

    void add(event::Service* sh, int events)
    {
        std::error_code ec;
        io_.add(sh, events | EPOLLONESHOT);
    }

    void del(event::Service* sh)
    {
        io_.remove(sh);
    }

    void queue_reconnect(event::Service* sh) noexcept
    {
        reconnect_q_.push_back(sh);
    }

    void run()
    {
        io_.run();
    }
};

class Session : public event::Service
{
private:
    enum _states
    {
        STATE_TCP_CONNECT,
        STATE_TCP_CONNECTING,
        STATE_TLS_HANDSHAKING,
    };

private:
    SessionManager& io_;
    int id_;
    std::unique_ptr<tls::Handle> tls_;
    std::chrono::time_point<std::chrono::steady_clock> ts_;
    enum _states state_;
    network::Socket<network::Tcp> sd;

public:
    Session(SessionManager& io, int id) noexcept
        : Service(io.io_)
        , io_(io)
        , id_(id)
        , state_(STATE_TCP_CONNECT)
    {
        log::debug("{}: peer is created", id);
    }

    virtual ~Session()
    {
        disconnect();
    }

    bool next_state()
    {
        switch (state_)
        {
        case STATE_TCP_CONNECT:
            return tcp_connect();
        case STATE_TCP_CONNECTING:
            return tcp_connect_try_finish();
        case STATE_TLS_HANDSHAKING:
            return tls_handshake();
        default:
            throw std::system_error(
                std::make_error_code(std::errc::not_supported));
        }
        return false;
    }

private:
    void poll_for_read()
    {
        io_.add(this, EPOLLIN | EPOLLERR);
    }

    void poll_for_write()
    {
        io_.add(this, EPOLLOUT | EPOLLERR);
    }

    void del_from_poll()
    {
        io_.del(this);
    }

    bool tls_handshake()
    {
        using namespace std::chrono;
        std::error_code ec;

        state_ = STATE_TLS_HANDSHAKING;

        if (!tls_)
        {
            tls_ = std::make_unique<tls::Handle>(*io_.ctx_);
            tls_->setSocket(sd.get());
            BIO_set_tcp_ndelay(sd.get(), true);
        }

        auto want = tls_->handshake();

        if (want == tls::Handle::Want::Nothing)
        {
            log::debug("has completed TLS handshake");
            disconnect();
            io_.queue_reconnect(this);
            return true;
        }
        else if (want == tls::Handle::Want::InputAndRetry)
        {
            poll_for_read();
            return false;
        }
        else if (want == tls::Handle::Want::OutputAndRetry)
        {
            poll_for_write();
            return false;
        }
        disconnect();
        return false;
    }

    bool handle_established_tcp_conn()
    {
        log::debug("has established TCP connection");
        return tls_handshake();
    }

    void handle_connect_error(std::error_code ec)
    {
        if (static_cast<std::errc>(ec.value()) ==
                std::errc::operation_in_progress ||
            static_cast<std::errc>(ec.value()) ==
                std::errc::resource_unavailable_try_again)
        {
            poll_for_write();
            return;
        }

        disconnect();
    }

    bool tcp_connect_try_finish()
    {
        log::info("try to finish TCP handshake");
        int ret = 0;
        size_t len = 4;
        std::error_code ec;
    
        network::GetSocketOption(sd.get(), SOL_SOCKET, SO_ERROR, &ret, &len, ec);

        if (!ec)
            return handle_established_tcp_conn();

        handle_connect_error(ec);
        return false;
    }

    bool tcp_connect()
    {
        sd = network::Socket<network::Tcp>();

        sd.open(network::Tcp::v4());

        std::error_code ec;
        network::SetNonBlocking(sd.get(), true, ec);

        sd.connect(io_.target_, ec);

        state_ = STATE_TCP_CONNECTING;

        // On on localhost connect() can complete instantly
        // even on non-blocking sockets (e.g. Tempesta FW case).
        if (!ec)
        {
            return handle_established_tcp_conn();
        }

        handle_connect_error(ec);
        return false;
    }

    void disconnect() noexcept
    {
        tls_.reset();

        if (sd.get() >= 0)
        {
            try
            {
                del_from_poll();
            }
            catch (std::system_error& e)
            {
                std::cerr << "ERROR disconnect: " << e.what() << std::endl;
            }

            // Disable TIME-WAIT state, close immediately.
            // This leads to connection terminations with RST and
            // on high traffic valume you may see large number of
            // ESTABLISHED connections, which will be terminated by
            // the OS on timeout.
            // https://github.com/tempesta-tech/tempesta/issues/1432
            struct linger sl;
            sl.l_onoff = 1;
            sl.l_linger = 0;
            setsockopt(sd.get(), SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

            sd.close();
        }

        state_ = STATE_TCP_CONNECT;
    }

    int fd() const override
    {
        return sd.get();
    }
};


class PerfCommand final : public Command
{
public:
    PerfCommand()
    {
        parser_.add("help, h", "Print help message");
        parser_.add("ip, i", utils::Value(&options_.address),
                    "Target IP address");
        parser_.add("port, p", utils::Value(&options_.port), "Target port");
    }

    ~PerfCommand() = default;

    std::string_view description() const override
    {
        return "perfomance testing for TLS connections";
    }

    void execute(const std::vector<std::string>& args) override
    {
        parser_.parse(args);

        if (parser_.isUsed("help"))
        {
            parser_.help(std::cout, "snet perf");
            return;
        }

        std::size_t activeSessions{0};
        std::size_t newSessions{1};

        auto ip = network::IPAddress::fromString(options_.address.c_str());
        network::Endpoint target(ip.value(), options_.port);

        SessionManager manager(target);
        std::list<std::shared_ptr<Session>> allSessions;

        for (newSessions = 0; activeSessions + newSessions < options_.clientCount;
             ++newSessions)
        {
            auto p = std::make_shared<Session>(manager, activeSessions++);
            allSessions.push_back(p);
            p->next_state();
        }



        manager.run();
    }

private:
    utils::OptionsParser parser_;
    Options options_;
};

REGISTER_COMMAND("perf", PerfCommand);

} // namespace snet
