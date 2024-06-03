#pragma once
#include <system_error>
#include <snet/tls/types.hpp>
#include <snet/tls/context.hpp>

namespace snet::tls
{

class Handle
{
public:
    explicit Handle(Context& ctx)
        : ssl_(SSL_new(ctx.ctx_))
    {
        if (!ssl_)
        {
            throw std::bad_alloc();
        }
    }

    virtual ~Handle() noexcept
    {
        SSL_free(ssl_);
    }

    int read(std::uint8_t* buffer, std::size_t bufferSize)
    {
        return SSL_read(ssl_, buffer,
                        bufferSize < INT_MAX ? static_cast<int>(bufferSize)
                                             : INT_MAX);
    }

    int write(const std::uint8_t* buffer, std::size_t bufferSize)
    {
        return SSL_write(ssl_, buffer,
                         bufferSize < INT_MAX ? static_cast<int>(bufferSize)
                                              : INT_MAX);
    }

    void setSocket(int fd, std::error_code& ec) noexcept
    {
        if (0 >= SSL_set_fd(ssl_, fd))
        {
            ec = GetLastError();
        }
    }

    void setSocket(int fd)
    {
        std::error_code ec;
        setSocket(fd, ec);
        THROW_IF_ERROR(ec);
    }

    void Shutdown()
    {
        SSL_shutdown(ssl_);
    }

    bool HandshakeDone() const
    {
        return (TLS_ST_OK == SSL_get_state(ssl_));
    }

    int GetError(int ret) const
    {
        return SSL_get_error(ssl_, ret);
    }

    void connect(std::error_code& ec) noexcept
    {
        if (0 >= SSL_connect(ssl_)) {
            ec = GetLastError();
        }
    }

    void connect()
    {
        std::error_code ec;
        connect(ec);
        THROW_IF_ERROR(ec);
    }

/*
    want perform(int (engine::* op)(void*, std::size_t),
    std::uint8_t* data, std::size_t length, std::error_code& ec,
    std::size_t* bytes_transferred)
{
  std::size_t pending_output_before = ::BIO_ctrl_pending(ext_bio_);
  ::ERR_clear_error();
  int result = (this->*op)(data, length);
  int ssl_error = ::SSL_get_error(ssl_, result);
  int sys_error = static_cast<int>(::ERR_get_error());
  std::size_t pending_output_after = ::BIO_ctrl_pending(ext_bio_);

  if (ssl_error == SSL_ERROR_SSL)
  {
    ec = asio::error_code(sys_error,
        asio::error::get_ssl_category());
    return pending_output_after > pending_output_before
      ? want_output : want_nothing;
  }

  if (ssl_error == SSL_ERROR_SYSCALL)
  {
    if (sys_error == 0)
    {
      ec = asio::ssl::error::unspecified_system_error;
    }
    else
    {
      ec = asio::error_code(sys_error,
          asio::error::get_ssl_category());
    }
    return pending_output_after > pending_output_before
      ? want_output : want_nothing;
  }

  if (result > 0 && bytes_transferred)
    *bytes_transferred = static_cast<std::size_t>(result);

  if (ssl_error == SSL_ERROR_WANT_WRITE)
  {
    ec = asio::error_code();
    return want_output_and_retry;
  }
  else if (pending_output_after > pending_output_before)
  {
    ec = asio::error_code();
    return result > 0 ? want_output : want_output_and_retry;
  }
  else if (ssl_error == SSL_ERROR_WANT_READ)
  {
    ec = asio::error_code();
    return want_input_and_retry;
  }
  else if (ssl_error == SSL_ERROR_ZERO_RETURN)
  {
    ec = asio::error::eof;
    return want_nothing;
  }
  else if (ssl_error == SSL_ERROR_NONE)
  {
    ec = asio::error_code();
    return want_nothing;
  }
  else
  {
    ec = asio::ssl::error::unexpected_result;
    return want_nothing;
  }
}
*/


protected:
    SSL* ssl_{nullptr};
};

} // namespace snet::tls