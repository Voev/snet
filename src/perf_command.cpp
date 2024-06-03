#include <chrono>
#include <atomic>
#include <snet/command.hpp>
#include <snet/command_dispatcher.hpp>
#include <snet/utils/options_parser.hpp>
#include <snet/tls/context.hpp>
#include <snet/tls/handle.hpp>
#include <snet/event/epoll.hpp>
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

struct SocketHandler : public std::enable_shared_from_this<SocketHandler>
{
    virtual ~SocketHandler(){};
    virtual bool next_state() = 0;

    network::Socket<network::Tcp> sd;
};

class IO
{
private:
    friend class Peer;
    static const size_t N_EVENTS = 128;
    static const size_t TO_MSEC = 5;

private:
    event::Epoll ed_;
    int ev_count_;
    tls::Context ctx_;
    event::Epoll::Event events_[N_EVENTS] = {};
    std::list<std::shared_ptr<SocketHandler>> reconnect_q_;
    std::list<std::shared_ptr<SocketHandler>> backlog_;
    network::Endpoint target_;

public:
    IO(const network::Endpoint& target)
        : ed_()
        , ev_count_(0)
        , ctx_(TLS_client_method())
        , target_(target)
    {
        ctx_.setMinVersion(tls::ProtocolVersion::TLSv1_2);
        ctx_.setMaxVersion(tls::ProtocolVersion::TLSv1_3);
        ctx_.setVerifyCallback(tls::VerifyMode::None, nullptr);
    }

    ~IO()
    {
        reconnect_q_.clear();
    }

    void add(SocketHandler* sh, int events)
    {
        std::error_code ec;
        ed_.modify(sh, sh->sd.get(), events | EPOLLONESHOT, ec);

        if ((std::errc)ec.value() == std::errc::no_such_file_or_directory)
            ed_.add(sh, sh->sd.get(), events | EPOLLONESHOT);
    }

    void del(SocketHandler* sh)
    {
        ed_.del(sh->sd.get());
    }

    void queue_reconnect(std::shared_ptr<SocketHandler> sh) noexcept
    {
        reconnect_q_.push_back(sh);
    }

    void wait()
    {
        std::error_code ec;
        do
        {
            ev_count_ = ed_.wait(events_, N_EVENTS, TO_MSEC, ec);
            if (ev_count_ < 0)
            {
                if (static_cast<std::errc>(ec.value()) ==
                    std::errc::interrupted)
                    continue;
                throw ec;
            }
        } while (false);
    }

    SocketHandler* next_sk() noexcept
    {
        if (ev_count_)
            return (SocketHandler*)events_[--ev_count_].data.ptr;
        return NULL;
    }

    void backlog() noexcept
    {
        backlog_.swap(reconnect_q_);
    }

    std::shared_ptr<SocketHandler> next_backlog() noexcept
    {
        if (backlog_.empty())
            return NULL;

        auto sh = backlog_.front();
        backlog_.pop_front();
        return sh;
    }
};

class Peer : public SocketHandler
{
private:
    enum _states
    {
        STATE_TCP_CONNECT,
        STATE_TCP_CONNECTING,
        STATE_TLS_HANDSHAKING,
    };

private:
    IO& io_;
    int id_;
    std::unique_ptr<tls::Handle> tls_;
    std::chrono::time_point<std::chrono::steady_clock> ts_;
    enum _states state_;

public:
    Peer(IO& io, int id) noexcept
        : io_(io)
        , id_(id)
        , state_(STATE_TCP_CONNECT)
    {
        dbg_status("created");
    }

    virtual ~Peer()
    {
        disconnect();
    }

    bool next_state() final override
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

    void dbg_status(const char* msg) noexcept
    {
        log::debug(msg);
    }

    bool tls_handshake()
    {
        using namespace std::chrono;

        state_ = STATE_TLS_HANDSHAKING;

        if (!tls_)
        {
            tls_ = std::make_unique<tls::Handle>(io_.ctx_);
            tls_->setSocket(sd.get());
            BIO_set_tcp_ndelay(sd.get(), true);
        }

        tls_->connect();
        int r = 1;
        // if (r == 1)
        {

            dbg_status("has completed TLS handshake");
            disconnect();
            io_.queue_reconnect(shared_from_this());
            return true;
        }

        switch (tls_->GetError(r))
        {
        case SSL_ERROR_WANT_READ:
            poll_for_read();
            break;
        case SSL_ERROR_WANT_WRITE:
            poll_for_write();
            break;
        default:
            disconnect();
        }
        return false;
    }

    bool handle_established_tcp_conn()
    {
        // del_from_poll(); // not needed as we're using EPOLLONESHOT
        dbg_status("has established TCP connection");
        return tls_handshake();
    }

    void handle_connect_error(int err)
    {
        if (err == EINPROGRESS || err == EAGAIN)
        {
            errno = 0;

            // Continue to wait on the TCP handshake.
            // add_to_poll();
            poll_for_write();

            return;
        }

        errno = 0;
        disconnect();
    }

    bool tcp_connect_try_finish()
    {
        int ret = 0;
        socklen_t len = 4;

        if (getsockopt(sd.get(), SOL_SOCKET, SO_ERROR, &ret, &len))
            throw std::runtime_error("cannot get a socket connect() status");

        if (!ret)
            return handle_established_tcp_conn();

        handle_connect_error(ret);
        return false;
    }

    bool tcp_connect()
    {
        sd = network::Socket<network::Tcp>();

        sd.open(network::Tcp::v4());

        // fcntl(sd, F_SETFL, fcntl(sd, F_GETFL, 0) | O_NONBLOCK);

        std::error_code ec;
        sd.connect(io_.target_, ec);

        state_ = STATE_TCP_CONNECTING;

        // On on localhost connect() can complete instantly
        // even on non-blocking sockets (e.g. Tempesta FW case).
        if (!ec)
            return handle_established_tcp_conn();

        handle_connect_error(errno);
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
};

bool end_of_work() noexcept
{
    // We can make bit more handshakes than was specified by a user -
    // not a big deal.
    return finish;
}

void io_loop(const Options& options)
{
    std::size_t active_peers = 0;
    std::size_t new_peers = 1; // std::min(g_opt.n_peers, PEERS_SLOW_START);

    auto ip = network::IPAddress::fromString(options.address.c_str());
    network::Endpoint target(ip.value(), options.port);

    IO io(target);
    std::list<std::shared_ptr<SocketHandler>> all_peers;

    while (!end_of_work())
    {
        // We implement slow start of number of concurrent TCP
        // connections, so active_peers and peers dynamically grow in
        // this loop.
        for (; active_peers < options.clientCount && new_peers; --new_peers)
        {
            auto p = std::make_shared<Peer>(io, active_peers++);
            all_peers.push_back(p);

            if (p->next_state() && active_peers + new_peers < options.clientCount)
                ++new_peers;
        }

        io.wait();
        while (auto p = io.next_sk())
        {
            if (p->next_state() && active_peers + new_peers < options.clientCount)
                ++new_peers;
        }

        // Process disconnected sockets from the backlog.
        io.backlog();
        while (!finish)
        {
            auto p = io.next_backlog();
            if (!p)
                break;
            if (p->next_state() && active_peers + new_peers < options.clientCount)
                ++new_peers;
        }
    }
}

class PerfCommand final : public Command
{
public:
    PerfCommand()
    {
        parser_.add("help, h", "Print help message",
                    utils::OptionType::NoValue);
        parser_.add("ip, i", "Target IP address",
                    utils::OptionType::SingleValue);
        parser_.add("port, p", "Target port", utils::OptionType::SingleValue);
    }

    ~PerfCommand() = default;

    std::string_view description() const override
    {
        return "my desc";
    }

    void execute(const std::vector<std::string>& args) override
    {
        parser_.parse(args);
        options.port = std::stoi(parser_.get("port"));
        options.address = parser_.get("ip");

        io_loop(options);
    }

private:
    utils::ArgumentParser parser_;
    Options options;
};

REGISTER_COMMAND("perf", PerfCommand);

} // namespace snet
