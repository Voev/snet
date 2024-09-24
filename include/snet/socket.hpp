
#pragma once
#include <string>
#include <stdexcept>
#include <openssl/bio.h>
#include <snet/address.hpp>

class Socket
{
public:
    explicit Socket(int fd = 0)
        : fd_(fd)
    {
        if (!fd_)
        {
            fd_ = BIO_socket(AF_INET, SOCK_STREAM, 0, 0);
            if (fd_ < 0 || !BIO_socket_nbio(fd_, 1))
            {
                throw std::runtime_error("invalid socket");
            }
        }
        sock_ = BIO_new_socket(fd_, BIO_NOCLOSE);
        if (!sock_)
        {
            throw std::runtime_error("BIO_new_socket() failed");
        }
    }

    virtual ~Socket()
    {
        BIO_free_all(sock_);
        BIO_closesocket(fd_);
    }

    int GetFd() const
    {
        return fd_;
    }

    int Read(void* buf, size_t bufSize)
    {
        return BIO_read(sock_, buf, bufSize);
    }

    int Write(const void* buf, int bufSize)
    {
        return BIO_write(sock_, buf, bufSize);
    }

    int Write(const std::string& data)
    {
        return Write(data.c_str(), static_cast<int>(data.length()));
    }

protected:
    int fd_;

private:
    BIO* sock_;
};

class ConnectSocket : public Socket
{
public:
    ConnectSocket() = default;
    virtual ~ConnectSocket() = default;

    int Connect(const Address& addr)
    {
        return BIO_connect(fd_, addr.Get0(), 0);
    }
};

class AcceptSocket : public Socket
{
public:
    AcceptSocket() = default;
    virtual ~AcceptSocket() = default;

    int Listen(const Address& addr)
    {
        return BIO_listen(fd_, addr.Get0(), BIO_SOCK_REUSEADDR);
    }

    int Accept(Address& addr)
    {
        return BIO_accept_ex(fd_, addr.Get0(), BIO_SOCK_NONBLOCK);
    }
};
