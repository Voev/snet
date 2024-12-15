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

#include <casket/opt/option_parser.hpp>
#include <casket/log/log_manager.hpp>

#include <snet/cli/command_dispatcher.hpp>
#include <snet/utils/error_code.hpp>
#include <snet/event/epoll.hpp>

#include <snet/socket.hpp>
#include <snet/tls.hpp>

static const size_t kDefaultThreadCount = 1;
static const size_t kDefaultSessionCount = 1;
static const size_t kSessionCountForSlowStart = 10;
static const size_t kLatencyItems = 1024;

using namespace std::chrono;
using namespace std::chrono_literals;

using namespace casket;
using namespace casket::log;
using namespace snet;
using namespace snet::event;
using namespace snet::socket;

using Clock = steady_clock;
using TimePoint = time_point<Clock>;

struct Options
{
    std::string versions;
    std::string cipher;
    std::string curve;
    std::string sni;
    std::string input;
    size_t handshakeLimit{std::numeric_limits<size_t>::max()};
    size_t sessionLimit{kDefaultSessionCount};
    size_t threadLimit{kDefaultThreadCount};
    int timeout{0};
    bool debug{false};
    bool quiet{false};
    bool useTickets{false};
    bool advTickets{false};
};

struct Statistics
{
    std::atomic<uint64_t> totalHandshakes;
    std::atomic<int32_t> tcpHandshakes;
    std::atomic<int32_t> tcpConnections;
    std::atomic<int32_t> tlsHandshakes;
    std::atomic<int32_t> tlsConnections;
    std::atomic<int32_t> errorCount;
    int32_t noFalseSharing[9];

    TimePoint startTime;
    int32_t measures;
    int32_t maxHandshakes;
    int32_t minHandshakes;
    int32_t avgHandshakes;
    std::vector<int32_t> handshakeHistory;
};

static Statistics stat;

struct GlobalLatencyStats
{
    std::mutex lock;
    std::vector<double> stat;
    double sum;
};

static GlobalLatencyStats gLatencyStats;

class LocalLatencyStats
{
public:
    LocalLatencyStats() noexcept
        : i_(0)
        , di_(1)
    {
    }

    void update(double dt) noexcept
    {
        if (dt <= 0.0)
        {
            log::error("Bad latency value - {}", dt);
            return;
        }

        stat_[i_] = dt;
        i_ += di_;

        if (i_ >= kLatencyItems)
        {
            i_ = 0;
            if (++di_ > kLatencyItems / 4)
            {
                di_ = 1;
            }
        }
    }

    void dump() noexcept
    {
        std::lock_guard<std::mutex> guard(gLatencyStats.lock);
        for (auto l : stat_)
        {
            gLatencyStats.stat.push_back(l);
            gLatencyStats.sum += l;
        }
    }

private:
    std::array<double, kLatencyItems> stat_;
    size_t i_;
    size_t di_;
};

static thread_local LocalLatencyStats gLocalLatencyStats;

class SessionManager;
class Session final
{
private:
    enum class State
    {
        Preconnect,
        InTcpHandshaking,
        InTlsHandshaking
    };

private:
    SessionManager& manager_;
    Socket socket_;
    Endpoint ep_;
    std::unique_ptr<tls::Connection> tls_;
    tls::SslSessionPtr session_;
    TimePoint start_;
    State state_;
    std::string sni_;
    bool reuseSession_;
    int id_;

public:
    Session(SessionManager& manager, Endpoint ep, bool reuseSession, std::string sni,
            int id) noexcept;

    ~Session() noexcept;

    void handleReadEvent();

    void handleWriteEvent();

    void connect() {
        state_ = State::Preconnect;
        handleWriteEvent();
    }

    void disconnect() noexcept;

    int get() const
    {
        return socket_.get();
    }

private:
    bool handleEstablishedTcpConn();
    void handleConnectError(const std::error_code ec);

    bool doTcpConnect();
    bool doTcpConnected();
    bool doTlsHandshake();
};

class SessionManager
{
private:
    static const size_t kEventCount = 128;
    static const size_t kTimeout = 5;

private:
    Epoll epoll_;
    std::array<Epoll::Event, kEventCount> events_;
    int eventCount_;
    tls::ClientSettings settings_;

public:
    SessionManager(const Options& options)
        : epoll_()
        , events_()
        , eventCount_(0)
        , settings_()
    {
        if (!options.versions.empty())
        {
            auto versions = tls::ParseProtocolVersionRange(options.versions);
            if (!versions.has_value())
            {
                throw std::runtime_error("");
            }

            auto [min, max] = versions.value();
            settings_.setMinVersion(min);
            settings_.setMaxVersion(max);
        }

        if (!options.useTickets)
        {
            if (!options.advTickets)
                settings_.setOptions(SSL_OP_NO_TICKET);
            settings_.setSessionCacheMode(tls::SessionCacheMode::CacheOff |
                                          tls::SessionCacheMode::CacheNoInternal);
        }
        else
        {
            settings_.setSessionCacheMode(tls::SessionCacheMode::CacheClient |
                                          tls::SessionCacheMode::CacheNoAutoClear);
        }

        if (!options.cipher.empty())
        {
            settings_.setCipherList(options.cipher);
        }

        if (!options.curve.empty())
        {
            settings_.setGroupsList(options.curve);
        }

        settings_.setVerifyCallback(tls::VerifyMode::None, nullptr);
    }

    ~SessionManager()
    {
    }

    void add(Session* sh, Epoll::EventMask events)
    {
        std::error_code ec;
        epoll_.modify(sh, sh->get(), snet::event::OneShot | events, ec);

        if (ec == std::errc::no_such_file_or_directory)
        {
            ec.clear();
            epoll_.add(sh, sh->get(), events, ec);
        }
        if (ec)
            log::error("add(): {}", ec.message());
    }

    void del(Session* sh)
    {
        std::error_code ec;
        epoll_.del(sh->get(), ec);
        if (ec)
            log::error("del(): {}", ec.message());
    }

    std::unique_ptr<tls::Connection> makeConnection()
    {
        return std::make_unique<tls::Connection>(settings_);
    }

    void handleEvents()
    {
        std::error_code ec;
        int numEvents = epoll_.wait(events_.data(), events_.size(), kTimeout, ec);

        for (int i = 0; i < numEvents; ++i)
        {
            auto* session = static_cast<Session*>(events_[i].data.ptr);
            if (events_[i].events & (EPOLLERR | EPOLLHUP))
            {
                session->disconnect();
            }
            else if (events_[i].events & EPOLLIN)
            {
                session->handleReadEvent();
            }
            else if (events_[i].events & EPOLLOUT)
            {
                session->handleWriteEvent();
            }
        }
    }
};

Session::Session(SessionManager& manager, Endpoint ep, bool reuseSession, std::string sni,
                 int id) noexcept
    : manager_(manager)
    , ep_(ep)
    , state_(State::Preconnect)
    , sni_(std::move(sni))
    , reuseSession_(reuseSession)
    , id_(id)
{
    log::debug("peer {} created", id_);
}

Session::~Session() noexcept
{
    disconnect();
}

void Session::handleReadEvent()
{
    if (state_ == State::InTlsHandshaking)
    {
        doTlsHandshake();
    }
}

void Session::handleWriteEvent()
{
    if (state_ == State::Preconnect)
    {
        doTcpConnect();
    }
    else if (state_ == State::InTcpHandshaking)
    {
        doTcpConnected();
    }
    else if (state_ == State::InTlsHandshaking)
    {
        doTlsHandshake();
    }
}

bool Session::handleEstablishedTcpConn()
{
    log::debug("peer {}: has established TCP connection", id_);
    stat.tcpHandshakes--;
    stat.tcpConnections++;
    return doTlsHandshake();
}

void Session::handleConnectError(const std::error_code ec)
{
    if (ec == std::errc::operation_in_progress || ec == std::errc::resource_unavailable_try_again)
    {
        manager_.add(this, Write);
        return;
    }

    if (!stat.tcpConnections)
        throw std::runtime_error("cannot establish even one TCP connection");

    stat.tcpHandshakes--;
    disconnect();
}

bool Session::doTcpConnect()
{
    socket_.open(ep_.isIPv4() ? Tcp::v4() : Tcp::v6());

    std::error_code ec;
    setNonBlocking(socket_.get(), true, ec);
    snet::utils::ThrowIfError(ec);
    socket_.connect(ep_, ec);

    stat.tcpHandshakes++;
    state_ = State::InTcpHandshaking;

    if (!ec)
        return handleEstablishedTcpConn();

    handleConnectError(ec);
    return false;
}

bool Session::doTcpConnected()
{
    auto ec = getSocketError(socket_.get());
    if (!ec)
        return handleEstablishedTcpConn();

    handleConnectError(ec);
    return false;
}

bool Session::doTlsHandshake()
{
    using namespace std::chrono;

    state_ = State::InTlsHandshaking;

    if (!tls_)
    {
        tls_ = manager_.makeConnection();

        tls_->setSocket(socket_.get());

        BIO_set_tcp_ndelay(socket_.get(), true);

        if (reuseSession_ && session_)
        {
            tls_->setSession(session_);
        }

        if (!sni_.empty())
        {
            tls_->setExtHostName(sni_);
        }

        stat.tlsHandshakes++;
        start_ = Clock::now();
    }

    auto want = tls_->handshake();
    if (want == tls::Connection::Want::Nothing)
    {
        const duration<double, std::milli> latency = Clock::now() - start_;
        gLocalLatencyStats.update(latency.count());

        log::debug("peer {}: has completed TLS handshake", id_);
        stat.tlsHandshakes--;
        stat.tlsConnections++;
        stat.totalHandshakes++;
        disconnect();
        stat.tcpConnections--;

        connect();
        return true;
    }

    switch (want)
    {
    case tls::Connection::Want::InputAndRetry:
        manager_.add(this, Read);
        break;
    case tls::Connection::Want::OutputAndRetry:
        manager_.add(this, Write);
        break;
    default:
        if (!stat.totalHandshakes)
            throw std::runtime_error("cannot establish even one TLS"
                                     " connection");
        stat.tlsHandshakes--;
        stat.errorCount++;
        disconnect();
        stat.tcpConnections--;
    }
    return false;
}

void Session::disconnect() noexcept
{
    if (tls_)
    {
        if (reuseSession_)
        {
            tls_->shutdown();
            session_ = tls_->getSession();
        }
        tls_.reset();
    }

    if (socket_.get() >= 0)
    {
        manager_.del(this);
        std::error_code ec;
        setLinger(socket_.get(), 1, 0, ec);
        socket_.close();
    }
}

void PrintOptions(const Endpoint& ep, const Options& options)
{
    std::cout << "Running TLS benchmark with following settings:\n"
              << "Host:        " << ep.toString() << "\n"
              << "TLS version: " << options.versions << "\n"
              << "Cipher:      " << (!options.cipher.empty() ? options.cipher : "default") << "\n"
              << "TLS tickets: "
              << (options.useTickets ? "on\n" : !options.advTickets ? "off\n" : "advertise\n")
              << "Duration:    " << options.timeout << "\n"
              << std::endl;
}

std::atomic<bool> bFinish(false);

void sig_handler(int signum) noexcept
{
    (void)signum;
    bFinish = true;
}

void UpdateLimits(Options& options) noexcept
{
    struct rlimit open_file_limit = {};
    rlim_t req_fd_n = (options.sessionLimit + 4) * options.threadLimit;

    getrlimit(RLIMIT_NOFILE, &open_file_limit);
    if (open_file_limit.rlim_cur > req_fd_n)
        return;

    if (!options.quiet)
        std::cout << "set open files limit to " << req_fd_n << std::endl;
    open_file_limit.rlim_cur = req_fd_n;
    if (setrlimit(RLIMIT_NOFILE, &open_file_limit))
    {
        options.sessionLimit = open_file_limit.rlim_cur / (options.threadLimit + 4);
        std::cerr << "WARNING: required " << req_fd_n
                  << " (peers_number * threads_number), but setrlimit(2)"
                     " fails for this rlimit. Try to run as root or"
                     " decrease the numbers. Continue with "
                  << options.sessionLimit << " peers" << std::endl;
        if (!options.sessionLimit)
        {
            std::cerr << "ERROR: cannot run with no peers" << std::endl;
            exit(3);
        }
    }
}

void UpdateStatistics(const Options& options) noexcept
{
    auto tls_conns = stat.tlsConnections.load();
    auto now(Clock::now());
    auto dt = duration_cast<milliseconds>(now - stat.startTime).count();

    stat.startTime = now;
    stat.tlsConnections -= tls_conns;

    int32_t curr_hs = (size_t)(1000 * tls_conns) / dt;
    if (!options.quiet)
        std::cout << "TLS hs in progress " << stat.tlsHandshakes << " [" << curr_hs << " h/s],"
                  << " TCP open conns " << stat.tcpConnections << " [" << stat.tcpHandshakes
                  << " hs in progress],"
                  << " Errors " << stat.errorCount << std::endl;

    stat.measures++;
    if (stat.maxHandshakes < curr_hs)
        stat.maxHandshakes = curr_hs;
    if (curr_hs && (stat.minHandshakes > curr_hs || !stat.minHandshakes))
        stat.minHandshakes = curr_hs;
    stat.avgHandshakes = (stat.avgHandshakes * (stat.measures - 1) + curr_hs) / stat.measures;
    if (stat.handshakeHistory.size() == 100)
        std::cerr << "WARNING: benchmark is running for too long"
                  << " last history won't be stored" << std::endl;
    if (stat.handshakeHistory.size() <= 100)
        stat.handshakeHistory.push_back(curr_hs);
}

void DumpStatistics() noexcept
{
    auto handshakeItems = stat.handshakeHistory.size();
    auto latencyItems = gLatencyStats.stat.size();

    if (handshakeItems < 1 || latencyItems < 1)
    {
        std::cerr << "ERROR: not enough statistics collected" << std::endl;
        return;
    }

    std::sort(stat.handshakeHistory.begin(), stat.handshakeHistory.end(), std::greater<int32_t>());
    std::sort(gLatencyStats.stat.begin(), gLatencyStats.stat.end(), std::less<int32_t>());

    std::cout << "========================================" << std::endl;
    std::cout << " TOTAL:           SECONDS " << stat.measures << "; HANDSHAKES "
              << stat.totalHandshakes << std::endl;
    std::cout << " HANDSHAKES/sec: "
              << " MIN " << stat.minHandshakes << "; AVG "
              << stat.avgHandshakes
              // 95% handshakes are faster than this number.
              << "; 95P " << stat.handshakeHistory[handshakeItems * 95 / 100] << "; MAX "
              << stat.maxHandshakes << std::endl;

    std::cout << " LATENCY (ms):   "
              << " MIN " << gLatencyStats.stat.front() << "; AVG "
              << gLatencyStats.sum / latencyItems
              // 95% latencies are smaller than this one.
              << "; 95P " << gLatencyStats.stat[latencyItems * 95 / 100] << "; MAX "
              << gLatencyStats.stat.back() << std::endl;
}

bool EndOfWork(const Options& options) noexcept
{
    return bFinish || stat.totalHandshakes >= options.handshakeLimit;
}

void ProcessLoop(const Options& options, const Endpoint& ep)
{
    size_t activeSessions = 0;
    SessionManager manager(options);
    std::list<Session*> allSessions;

    for (; activeSessions < options.sessionLimit; ++activeSessions)
    {
        Session* p = new Session(manager, ep, options.useTickets, options.sni, activeSessions++);
        allSessions.push_back(p);
        p->connect();
    }

    while (!EndOfWork(options))
    {
        manager.handleEvents();
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
        parser_.add("to, T", opt::Value(&options_.timeout), "Duration of the test (in seconds)");
        parser_.add("limit, l", opt::Value(&options_.sessionLimit),
                    "Limit parallel connections for each thread");
        parser_.add("conn, n", opt::Value(&options_.handshakeLimit),
                    "Total number of handshakes to establish");
        parser_.add("threads, t", opt::Value(&options_.threadLimit), "Number of threads");
        parser_.add("tls", opt::Value(&options_.versions), "Set TLS version for handshake");
        parser_.add("input, i", opt::Value(&options_.input), "Target remote host");
    }

    ~PerfCommand() = default;

    void execute(const std::vector<std::string_view>& args) override
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

        signal(SIGTERM, sig_handler);
        signal(SIGINT, sig_handler);

        SSL_library_init();
        SSL_load_error_strings();

        ResolverOptions resolverOptions;
        resolverOptions.allowDns(true);
        resolverOptions.expectPort(true);
        resolverOptions.bindable(false);

        snet::socket::Resolver resolver;
        auto it = resolver.resolve(options_.input, resolverOptions);
        auto ep = *it;

        if (!options_.quiet)
        {
            PrintOptions(ep, options_);
        }
        UpdateLimits(options_);

        std::vector<std::thread> threads(options_.threadLimit);
        for (size_t i = 0; i < options_.threadLimit; ++i)
        {
            log::debug("thread {}: created", i + 1);
            threads[i] = std::thread([&]() {
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
        stat.startTime = startProgram;

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
                    bFinish = true;
                }
            }
        }

        for (auto& t : threads)
        {
            t.join();
        }

        DumpStatistics();
    }

private:
    opt::OptionParser parser_;
    Options options_;
};

REGISTER_COMMAND("perf", "Perfomance testing for TLS connections", PerfCommand);

} // namespace snet
