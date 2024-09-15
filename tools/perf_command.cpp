#include <sys/resource.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <csignal>
#include <chrono>
#include <iostream>
#include <list>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/tls1.h>

#include <snet/cmd/command_dispatcher.hpp>
#include <snet/opt/option_parser.hpp>
#include <snet/ip/ip_address.hpp>
#include <snet/socket/socket.hpp>
#include <snet/socket/tcp.hpp>
#include <snet/socket/endpoint.hpp>
#include <snet/utils/error_code.hpp>
#include <snet/event/epoll.hpp>
#include <snet/log/log_manager.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/tls_utils.hpp>

static const int DEFAULT_THREADS = 1;
static const int DEFAULT_PEERS = 1;
static const int PEERS_SLOW_START = 10;
static const int LATENCY_N = 1024;

using namespace std::chrono;
using namespace std::chrono_literals;

using namespace snet;
using namespace snet::event;
using namespace snet::log;
using namespace snet::tls;

using Clock = steady_clock;
using TimePoint = time_point<Clock>;

struct Options
{
    std::string tls_vers;
    std::string cipher;
    std::string curve;
    std::string sni;
    std::string ip;
    size_t n_hs{std::numeric_limits<size_t>::max()};
    int nSessions{DEFAULT_PEERS};
    int n_threads{DEFAULT_THREADS};
    int timeout{0};
    uint16_t port{443};
    bool debug{false};
    bool quiet{false};
    bool use_tickets{false};
    bool adv_tickets{false};
};

struct Statistics
{
    std::atomic<uint64_t> tot_tls_handshakes;
    std::atomic<int32_t> tcp_handshakes;
    std::atomic<int32_t> tcp_connections;
    std::atomic<int32_t> tls_connections;
    std::atomic<int32_t> tls_handshakes;
    std::atomic<int32_t> error_count;
    int32_t __no_false_sharing[9];

    TimePoint stat_time;

    int32_t measures;
    int32_t max_hs;
    int32_t min_hs;
    int32_t avg_hs;
    std::vector<int32_t> hs_history;

    void start_count()
    {
        stat_time = Clock::now();
    }
} stat;

struct GlobalLatencyStats
{
    std::mutex lock;
    std::vector<double> stat;
    double acc_lat;
};

static GlobalLatencyStats gLatencyStats;

class LocalLatencyStats
{
public:
    LocalLatencyStats() noexcept
        : i_(0)
        , di_(1)
        , stat_({0})
    {
    }

    void update(double dt) noexcept
    {
        if (!dt)
        {
            log::debug("Bad zero latency");
            return;
        }
        stat_[i_] = dt;

        i_ += di_;

        if (i_ >= LATENCY_N)
        {
            i_ = 0;
            if (++di_ > LATENCY_N / 4)
                di_ = 1;
        }
    }

    void dump() noexcept
    {
        std::lock_guard<std::mutex> _(gLatencyStats.lock);
        for (auto l : stat_)
        {
            if (!l)
                break;
            gLatencyStats.stat.push_back(l);
            gLatencyStats.acc_lat += l;
        }
    }

private:
    unsigned int i_;
    unsigned int di_;
    std::array<double, LATENCY_N> stat_;
};

static thread_local LocalLatencyStats gLocalLatencyStats;

struct ISession
{
    virtual ~ISession() = default;
    virtual bool nextState() = 0;

    snet::socket::Socket sd;
};

class SessionManager
{
private:
    static const size_t N_EVENTS = 128;
    static const size_t TO_MSEC = 5;

private:
    snet::event::Epoll epoll_;
    snet::event::Epoll::Event events_[N_EVENTS];
    int ev_count_;
    SSL_CTX* tls_ctx_;
    std::list<ISession*> reconnect_q_;
    std::list<ISession*> backlog_;

public:
    SessionManager(const Options& options)
        : epoll_()
        , ev_count_(0)
        , tls_ctx_(nullptr)
    {
        tls_ctx_ = SSL_CTX_new(TLS_client_method());

        if (!options.tls_vers.empty())
        {
            auto versions = ParseVersionRange(options.tls_vers);
            if (!versions.has_value())
            {
                throw std::runtime_error("");
            }

            auto [min, max] = versions.value();
            SSL_CTX_set_min_proto_version(tls_ctx_, static_cast<long>(min));
            SSL_CTX_set_max_proto_version(tls_ctx_, static_cast<long>(max));
        }

        if (!options.use_tickets)
        {
            unsigned int mode = SSL_SESS_CACHE_OFF | SSL_SESS_CACHE_NO_INTERNAL;
            if (!options.adv_tickets)
                SSL_CTX_set_options(tls_ctx_, SSL_OP_NO_TICKET);
            SSL_CTX_set_session_cache_mode(tls_ctx_, mode);
        }
        else
        {
            unsigned int mode =
                SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_AUTO_CLEAR;
            SSL_CTX_set_session_cache_mode(tls_ctx_, mode);
        }

        if (!options.cipher.empty())
        {
            if (!SSL_CTX_set_cipher_list(tls_ctx_, options.cipher.c_str()))
                throw std::runtime_error("cannot set cipher");
        }
        if (!options.curve.empty())
            if (!SSL_CTX_set1_groups_list(tls_ctx_, options.curve.c_str()))
                throw std::runtime_error("cannot set elliptic curve");
        SSL_CTX_set_verify(tls_ctx_, SSL_VERIFY_NONE, nullptr);

        memset(events_, 0, sizeof(events_));
    }

    ~SessionManager()
    {
        reconnect_q_.clear();

        if (tls_ctx_)
            SSL_CTX_free(tls_ctx_);
    }

    void add(ISession* sh, Epoll::EventMask events)
    {
        std::error_code ec;
        epoll_.modify(sh, sh->sd.get(), snet::event::OneShot | events, ec);

        if (ec == std::errc::no_such_file_or_directory)
        {
            ec.clear();
            epoll_.add(sh, sh->sd.get(), events, ec);
        }
        if (ec)
            log::error("add(): {}", ec.message());
    }

    void del(ISession* sh)
    {
        std::error_code ec;
        epoll_.del(sh->sd.get(), ec);
        if (ec)
            log::error("del(): {}", ec.message());
    }

    void enqueueForReconnect(ISession* sh) noexcept
    {
        reconnect_q_.push_back(sh);
    }

    void wait()
    {
        std::error_code ec;
        while (true)
        {
            ev_count_ = epoll_.wait(events_, N_EVENTS, TO_MSEC, ec);
            if (ec == std::errc::interrupted)
                continue;

            if (!ec)
                break;

            THROW_IF_ERROR(ec);
        }
    }

    ISession* nextSession() noexcept
    {
        if (ev_count_)
        {
            ev_count_--;
            return (ISession*)events_[ev_count_].data.ptr;
        }
        return nullptr;
    }

    void backlog() noexcept
    {
        backlog_.swap(reconnect_q_);
    }

    ISession* nextBacklog() noexcept
    {
        if (backlog_.empty())
            return nullptr;

        ISession* sh = backlog_.front();
        backlog_.pop_front();
        return sh;
    }

    SSL* makePreconnection()
    {
        SSL* ctx = SSL_new(tls_ctx_);
        if (!ctx)
            throw std::runtime_error("cannot clone TLS context");
        return ctx;
    }
};

class Session final : public ISession
{
private:
    enum class State
    {
        Preconnect,
        InTcpHandshaking,
        InTlsHandshaking,
    };

private:
    SessionManager& manager_;
    int id_;
    SSL* tls_;
    SslSessionPtr session_;
    socket::Endpoint ep_;
    TimePoint start_;
    State state_;
    bool reuseSession_;
    std::string sni_;

public:
    Session(SessionManager& manager, socket::Endpoint ep, bool reuseSession,
            std::string sni, int id) noexcept
        : manager_(manager)
        , id_(id)
        , tls_(nullptr)
        , ep_(ep)
        , state_(State::Preconnect)
        , reuseSession_(reuseSession)
        , sni_(std::move(sni))
    {
        log::debug("peer {} created", id_);
    }

    ~Session() noexcept
    {
        disconnect();
    }

    bool nextState() final override
    {
        switch (state_)
        {
        case State::Preconnect:
            return doTcpConnect();
        case State::InTcpHandshaking:
            return doTcpConnected();
        case State::InTlsHandshaking:
            return doTlsHandshake();
        }
        return false;
    }

private:
    void pollForRead()
    {
        manager_.add(this, Read | Error);
    }

    void pollForWrite()
    {
        manager_.add(this, Write | Error);
    }

    void deleteFromPoll()
    {
        manager_.del(this);
    }

    bool handleEstablishedTcpConn()
    {
        // deleteFromPoll(); // not needed as we're using EPOLLONESHOT
        log::debug("peer {}: has established TCP connection", id_);
        stat.tcp_handshakes--;
        stat.tcp_connections++;
        return doTlsHandshake();
    }

    void handleConnectError(const std::error_code ec)
    {
        if (ec == std::errc::operation_in_progress ||
            ec == std::errc::resource_unavailable_try_again)
        {
            pollForWrite();
            return;
        }

        if (!stat.tcp_connections)
            throw std::runtime_error(
                "cannot establish even one TCP connection");

        stat.tcp_handshakes--;
        disconnect();
    }

    bool doTcpConnect()
    {
        sd.open(ep_.isIPv4() ? snet::socket::Tcp::v4()
                             : snet::socket::Tcp::v6());

        std::error_code ec;
        snet::socket::setNonBlocking(sd.get(), true, ec);
        THROW_IF_ERROR(ec);
        sd.connect(ep_, ec);

        stat.tcp_handshakes++;
        state_ = State::InTcpHandshaking;

        if (!ec)
            return handleEstablishedTcpConn();

        handleConnectError(ec);
        return false;
    }

    bool doTcpConnected()
    {
        auto ec = socket::getSocketError(sd.get());
        if (!ec)
            return handleEstablishedTcpConn();

        handleConnectError(ec);
        return false;
    }

    bool doTlsHandshake()
    {
        using namespace std::chrono;

        state_ = State::InTlsHandshaking;

        if (!tls_)
        {
            tls_ = manager_.makePreconnection();

            SSL_set_fd(tls_, sd.get());

            BIO_set_tcp_ndelay(sd.get(), true);

            if (reuseSession_ && session_)
            {
                SSL_set_session(tls_, session_);
            }

            if (!sni_.empty())
            {
                SSL_set_tlsext_host_name(tls_, sni_.c_str());
            }

            stat.tls_handshakes++;
            start_ = Clock::now();
        }

        int r = SSL_connect(tls_);
        if (r == 1)
        {
            auto end(Clock::now());
            const duration<double, std::milli> latency = start_ - end;
            gLocalLatencyStats.update(latency.count());

            log::debug("peer {}: has completed TLS handshake", id_);
            stat.tls_handshakes--;
            stat.tls_connections++;
            stat.tot_tls_handshakes++;
            disconnect();

            stat.tcp_connections--;
            manager_.enqueueForReconnect(this);
            return true;
        }

        switch (SSL_get_error(tls_, r))
        {
        case SSL_ERROR_WANT_READ:
            pollForRead();
            break;
        case SSL_ERROR_WANT_WRITE:
            pollForWrite();
            break;
        default:
            if (!stat.tot_tls_handshakes)
                throw std::runtime_error("cannot establish even one TLS"
                                         " connection");
            stat.tls_handshakes--;
            stat.error_count++;
            disconnect();
            stat.tcp_connections--;
        }
        return false;
    }

    void disconnect() noexcept
    {
        if (tls_)
        {
            if (reuseSession_)
            {
                SSL_shutdown(tls_);
                session_.reset(SSL_get1_session(tls_));
            }
            SSL_free(tls_);
            tls_ = nullptr;
        }
        if (sd.get() >= 0)
        {
            deleteFromPoll();
            std::error_code ec;
            socket::setLinger(sd.get(), 1, 0, ec);
            sd.close();
        }

        state_ = State::Preconnect;
    }
};

void PrintOptions(const Options& options)
{
    std::cout << "Running TLS benchmark with following settings:\n"
              << "Host:        " << options.ip << ":" << options.port << "\n"
              << "TLS version: " << options.tls_vers;
    std::cout << "Cipher:      "
              << (!options.cipher.empty() ? options.cipher : "default") << "\n"
              << "TLS tickets: "
              << (options.use_tickets
                      ? "on\n"
                      : !options.adv_tickets ? "off\n" : "advertise\n")
              << "Duration:    " << options.timeout << "\n"
              << std::endl;
}

std::atomic<bool> finish(false), start_stats(false);

void sig_handler(int signum) noexcept
{
    (void)signum;
    finish = true;
}

void UpdateLimits(Options& options) noexcept
{
    struct rlimit open_file_limit = {};
    rlim_t req_fd_n = (options.nSessions + 4) * options.n_threads;

    getrlimit(RLIMIT_NOFILE, &open_file_limit);
    if (open_file_limit.rlim_cur > req_fd_n)
        return;

    if (!options.quiet)
        std::cout << "set open files limit to " << req_fd_n << std::endl;
    open_file_limit.rlim_cur = req_fd_n;
    if (setrlimit(RLIMIT_NOFILE, &open_file_limit))
    {
        options.nSessions = open_file_limit.rlim_cur / (options.n_threads + 4);
        std::cerr << "WARNING: required " << req_fd_n
                  << " (peers_number * threads_number), but setrlimit(2)"
                     " fails for this rlimit. Try to run as root or"
                     " decrease the numbers. Continue with "
                  << options.nSessions << " peers" << std::endl;
        if (!options.nSessions)
        {
            std::cerr << "ERROR: cannot run with no peers" << std::endl;
            exit(3);
        }
    }
}

void UpdateStatistics(const Options& options) noexcept
{
    using namespace std::chrono;

    auto tls_conns = stat.tls_connections.load();

    auto now(steady_clock::now());
    auto dt = duration_cast<milliseconds>(now - stat.stat_time).count();

    stat.stat_time = now;
    stat.tls_connections -= tls_conns;

    int32_t curr_hs = (size_t)(1000 * tls_conns) / dt;
    if (!options.quiet)
        std::cout << "TLS hs in progress " << stat.tls_handshakes << " ["
                  << curr_hs << " h/s],"
                  << " TCP open conns " << stat.tcp_connections << " ["
                  << stat.tcp_handshakes << " hs in progress],"
                  << " Errors " << stat.error_count << std::endl;

    if (!start_stats)
        return;

    stat.measures++;
    if (stat.max_hs < curr_hs)
        stat.max_hs = curr_hs;
    if (curr_hs && (stat.min_hs > curr_hs || !stat.min_hs))
        stat.min_hs = curr_hs;
    stat.avg_hs = (stat.avg_hs * (stat.measures - 1) + curr_hs) / stat.measures;
    if (stat.hs_history.size() == 3600)
        std::cerr << "WARNING: benchmark is running for too long"
                  << " last history won't be stored" << std::endl;
    if (stat.hs_history.size() <= 3600)
        stat.hs_history.push_back(curr_hs);
}

void DumpStatistics() noexcept
{
    auto hsz = stat.hs_history.size();
    auto lsz = gLatencyStats.stat.size();

    if (!start_stats || hsz < 1 || lsz < 1)
    {
        std::cerr << "ERROR: not enough statistics collected" << std::endl;
        return;
    }

    std::sort(stat.hs_history.begin(), stat.hs_history.end(),
              std::greater<int32_t>());
    std::sort(gLatencyStats.stat.begin(), gLatencyStats.stat.end(),
              std::less<int32_t>());

    std::cout << "========================================" << std::endl;
    std::cout << " TOTAL:           SECONDS " << stat.measures
              << "; HANDSHAKES " << stat.tot_tls_handshakes << std::endl;
    std::cout << " HANDSHAKES/sec: "
              << " MAX " << stat.max_hs << "; AVG "
              << stat.avg_hs
              // 95% handshakes are faster than this number.
              << "; 95P " << stat.hs_history[hsz * 95 / 100] << "; MIN "
              << stat.min_hs << std::endl;

    std::cout << " LATENCY (ms):   "
              << " MIN " << gLatencyStats.stat.front() << "; AVG "
              << gLatencyStats.acc_lat / lsz
              // 95% latencies are smaller than this one.
              << "; 95P " << gLatencyStats.stat[lsz * 95 / 100] << "; MAX "
              << gLatencyStats.stat.back() << std::endl;
}

bool EndOfWork(const Options& options) noexcept
{
    return finish || stat.tot_tls_handshakes >= options.n_hs;
}

void ProcessLoop(const Options& options, const socket::Endpoint& ep)
{
    int activeSessions = 0;
    int newSessions = std::min(options.nSessions, PEERS_SLOW_START);
    SessionManager manager(options);
    std::list<ISession*> allSessions;

    while (!EndOfWork(options))
    {
        for (; activeSessions < options.nSessions && newSessions; --newSessions)
        {
            Session* p = new Session(manager, ep, options.use_tickets,
                                     options.sni, activeSessions++);
            allSessions.push_back(p);

            if (p->nextState() &&
                activeSessions + newSessions < options.nSessions)
                ++newSessions;
        }

        manager.wait();
        while (auto s = manager.nextSession())
        {
            if (s->nextState() &&
                activeSessions + newSessions < options.nSessions)
                ++newSessions;
        }

        manager.backlog();
        while (!finish)
        {
            auto s = manager.nextBacklog();
            if (!s)
                break;
            if (s->nextState() &&
                activeSessions + newSessions < options.nSessions)
                ++newSessions;
        }

        if (activeSessions == options.nSessions && !start_stats)
        {
            start_stats = true;
            std::cout << "( All peers are active, start to"
                      << " gather statistics )" << std::endl;
        }
    }

    for (auto s : allSessions)
        delete s;
}

namespace snet
{

class PerfCommand final : public cmd::Command
{
public:
    PerfCommand()
    {
        parser_.add("help, h", "Print help message");
        parser_.add("debug, d", "Run in debug mode");
        parser_.add("to, T", "Duration of the test (in seconds)");
        parser_.add("limit, l", opt::Value(&options_.nSessions),
                    "Limit parallel connections for each thread");
        parser_.add("conn, n", opt::Value(&options_.n_hs),
                    "Total number of handshakes to establish");
        parser_.add("threads, t", opt::Value(&options_.n_threads),
                    "Number of threads");
        parser_.add("tls", opt::Value(&options_.tls_vers),
                    "Set TLS version for handshake");
        parser_.add("ip, i", opt::Value(&options_.ip), "Target IP address");
        parser_.add("port, p", opt::Value(&options_.port), "Target port");
    }

    ~PerfCommand() = default;

    void execute(const std::vector<std::string>& args) override
    {
        parser_.parse(args);
        if (parser_.isUsed("help"))
        {
            parser_.help(std::cout);
            return;
        }

        LogManager::Instance().enable(Type::Console);
        if (parser_.isUsed("debug"))
        {
            LogManager::Instance().setLevel(Level::Debug);
        }

        if (!options_.quiet)
        {
            PrintOptions(options_);
        }
        UpdateLimits(options_);

        signal(SIGTERM, sig_handler);
        signal(SIGINT, sig_handler);

        SSL_library_init();
        SSL_load_error_strings();

        auto ip = snet::ip::IPAddress::fromString(options_.ip.c_str());
        if (!ip.has_value())
        {
            throw std::runtime_error("undefined IP address");
        }

        snet::socket::Endpoint ep(ip.value(), options_.port);

        std::vector<std::thread> thr(options_.n_threads);
        for (auto i = 0; i < options_.n_threads; ++i)
        {
            log::debug("thread {}: created", i + 1);
            thr[i] = std::thread([&]() {
                bool success{true};
                try
                {
                    ProcessLoop(options_, ep);
                }
                catch (std::exception& e)
                {
                    std::cerr << "ERROR: " << e.what() << std::endl;
                }

                if (success)
                    gLocalLatencyStats.dump();
            });
        }

        auto startProgram(Clock::now());
        stat.start_count();

        while (!EndOfWork(options_))
        {
            std::this_thread::sleep_for(1s);
            UpdateStatistics(options_);

            if (options_.timeout > 0)
            {
                auto endProgram(Clock::now());
                auto duration = duration_cast<seconds>(endProgram - startProgram).count();
                if (options_.timeout <= duration)
                {
                    finish = true;
                }
            }
        }

        for (auto& t : thr)
            t.join();

        DumpStatistics();
    }

private:
    opt::OptionParser parser_;
    Options options_;
};

REGISTER_COMMAND("perf", "Perfomance testing for TLS connections", PerfCommand);

} // namespace snet
