#pragma once
#include <openssl/ssl.h>
#include <snet/socket.hpp>
#include <snet/utils.hpp>
#include <stdexcept>

class SslHandle
{
  public:
    explicit SslHandle(SSL_CTX* ctx)
        : ssl_(SSL_new(ctx))
    {
        if (!ssl_)
        {
            throw std::bad_alloc();
        }
    }

    ~SslHandle()
    {
        SSL_free(ssl_);
    }

    int Read(void* buf, int num)
    {
        return SSL_read(ssl_, buf, num);
    }

    int Write(const void* buf, int num)
    {
        return SSL_write(ssl_, buf, num);
    }

    int Write(const std::string& buf)
    {
        return Write(buf.data(), static_cast<int>(buf.size()));
    }

    SSL* Get0() const
    {
        return ssl_;
    }

  protected:
    SSL* ssl_{nullptr};
};

class SslClientHandle : public SslHandle
{
  public:
    explicit SslClientHandle(const SslContext& ctx, const Socket& sock)
        : SslHandle(ctx.Get0())
    {
        SSL_set_fd(ssl_, sock.GetFd());
        SSL_set_connect_state(ssl_);
    }

    int Connect()
    {
        return SSL_connect(ssl_);
    }
};

class SslServerHandle : public SslHandle
{
  public:
    explicit SslServerHandle(const SslContext& ctx, const Socket& sock)
        : SslHandle(ctx.Get0())
    {
        SSL_set_fd(ssl_, sock.GetFd());
        SSL_set_accept_state(ssl_);
    }

    int Accept()
    {
        return SSL_accept(ssl_);
    }
};