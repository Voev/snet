
#pragma once
#include <string>
#include <openssl/bio.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>

#include <snet/ossl_types.hpp>
#include <snet/address.hpp>
#include <snet/utils.hpp>

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
        sock_.reset(BIO_new_socket(fd_, BIO_NOCLOSE));
        if (!sock_)
        {
            throw std::runtime_error("BIO_new_socket() failed");
        }
    }

    virtual ~Socket()
    {
        BIO_closesocket(fd_);
        fd_ = -1;
    }

    int GetFd() const
    {
        return fd_;
    }

    int Read(void* buf, size_t bufSize)
    {
        return BIO_read(sock_.get(), buf, bufSize);
    }

    int Write(const void* buf, int bufSize)
    {
        return BIO_write(sock_.get(), buf, bufSize);
    }

    int Write(const std::string& data)
    {
        return Write(data.c_str(), static_cast<int>(data.length()));
    }

  protected:
    int fd_;
    ossl::BioPtr sock_;
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
