#pragma once
#include <system_error>
#include <snet/tls/types.hpp>
#include <snet/tls/context.hpp>

namespace snet::tls
{

class Handle final
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

    explicit Handle(Context& ctx)
        : ssl_(SSL_new(ctx.ctx_))
    {
        if (!ssl_)
        {
            throw std::bad_alloc();
        }

        SSL_set_mode(ssl_, SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_set_mode(ssl_, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
        SSL_set_mode(ssl_, SSL_MODE_RELEASE_BUFFERS);

        BIO* intBio{nullptr};
        BIO_new_bio_pair(&intBio, 0, &extBio_, 0);
        SSL_set_bio(ssl_, intBio, intBio);

        if (ctx.side() == Side::Client)
        {
            SSL_set_connect_state(ssl_);
        }
        else
        {
            SSL_set_accept_state(ssl_);
        }
    }

    virtual ~Handle() noexcept
    {
        SSL_free(ssl_);
    }

    Handle(Handle&& other) noexcept
        : ssl_(other.ssl_)
        , extBio_(other.extBio_)
    {
        other.ssl_ = nullptr;
        other.extBio_ = nullptr;
    }

    Handle& operator=(Handle&& other) noexcept
    {
        if (this != &other)
        {
            ssl_ = other.ssl_;
            extBio_ = other.extBio_;
            other.ssl_ = nullptr;
            other.extBio_ = nullptr;
        }
        return *this;
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

    bool handshakeDone() const
    {
        return SSL_is_init_finished(ssl_);
    }

    Want handshake()
    {
        Operation op = std::bind(&Handle::doHandshake, this, std::placeholders::_1,
                                 std::placeholders::_2);
        return perform(op, nullptr, 0, 0);
    }

    Want shutdown()
    {
        Operation op = std::bind(&Handle::doShutdown, this, std::placeholders::_1,
                                 std::placeholders::_2);
        return perform(op, nullptr, 0, 0);
    }

    Want read(std::uint8_t* data, const std::size_t dataLength,
              std::size_t& bytesTransferred)
    {
        if (dataLength == 0)
        {
            return Want::Nothing;
        }
        Operation op = std::bind(&Handle::doRead, this, std::placeholders::_1,
                                 std::placeholders::_2);
        return perform(op, data, dataLength, &bytesTransferred);
    }

    Want write(std::uint8_t* data, const std::size_t dataLength,
               std::size_t& bytesTransferred)
    {
        if (dataLength == 0)
        {
            return Want::Nothing;
        }
        Operation op = std::bind(&Handle::doWrite, this, std::placeholders::_1,
                                 std::placeholders::_2);
        return perform(op, const_cast<std::uint8_t*>(data), dataLength,
                       &bytesTransferred);
    }

private:
    Want perform(const Operation& op, void* data, std::size_t length,
                 std::size_t* bytesTransferred)
    {

        std::size_t pendingOutputBefore = BIO_ctrl_pending(extBio_);
        ERR_clear_error();
        int result = op(data, length);
        int sslError = SSL_get_error(ssl_, result);
        std::size_t pendingOutputAfter = BIO_ctrl_pending(extBio_);

        if (sslError == SSL_ERROR_SSL)
        {
            return pendingOutputAfter > pendingOutputBefore ? Want::Output
                                                            : Want::Nothing;
        }

        if (sslError == SSL_ERROR_SYSCALL)
        {
            return pendingOutputAfter > pendingOutputBefore ? Want::Output
                                                            : Want::Nothing;
        }

        if (result > 0 && bytesTransferred)
            *bytesTransferred = static_cast<std::size_t>(result);

        if (sslError == SSL_ERROR_WANT_WRITE)
        {
            return Want::OutputAndRetry;
        }
        else if (pendingOutputAfter > pendingOutputBefore)
        {
            return result > 0 ? Want::Output : Want::OutputAndRetry;
        }
        else if (sslError == SSL_ERROR_WANT_READ)
        {
            return Want::InputAndRetry;
        }
        return Want::Nothing;
    }

    int doHandshake(void*, std::size_t)
    {
        return SSL_do_handshake(ssl_);
    }

    int doShutdown(void*, std::size_t)
    {
        int result = SSL_shutdown(ssl_);
        if (result == 0)
            result = SSL_shutdown(ssl_);
        return result;
    }

    int doRead(void* data, std::size_t length)
    {
        return SSL_read(ssl_, data,
                        length < INT_MAX ? static_cast<int>(length) : INT_MAX);
    }

    int doWrite(void* data, std::size_t length)
    {
        return SSL_write(ssl_, data,
                         length < INT_MAX ? static_cast<int>(length) : INT_MAX);
    }

private:
    SSL* ssl_{nullptr};
    BIO* extBio_{nullptr};
};

} // namespace snet::tls