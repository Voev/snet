#pragma once
#include <functional>
#include <snet/tls/settings.hpp>
#include <snet/tls/types.hpp>

namespace snet::tls
{

class Connection final
{
public:
    using Operation = std::function<int(void*, std::size_t)>;

    enum class Want
    {
        AlreadyCreated = -3,
        InputAndRetry = -2,
        OutputAndRetry = -1,
        Nothing = 0,
        Output = 1
    };

    explicit Connection(Settings& settings);

    ~Connection() noexcept;

    Connection(Connection&& other) noexcept;

    Connection& operator=(Connection&& other) noexcept;

    void setSocket(int fd);

    void setSession(SSL_SESSION* session);

    SslSessionPtr getSession();

    void setExtHostName(std::string_view hostname);

    bool handshakeDone() const noexcept;

    Want handshake();

    Want shutdown();

    Want read(std::uint8_t* data, const std::size_t dataLength,
              std::size_t& bytesTransferred);

    Want write(std::uint8_t* data, const std::size_t dataLength,
               std::size_t& bytesTransferred);

private:
    Want perform(const Operation& op, void* data, std::size_t length,
                 std::size_t* bytesTransferred);

    int doHandshake(void*, std::size_t);

    int doShutdown(void*, std::size_t);

    int doRead(void* data, std::size_t length);

    int doWrite(void* data, std::size_t length);

private:
    SslPtr ssl_;
    BioPtr extBio_;
};

} // namespace snet::tls