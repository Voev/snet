#pragma once
#include <array>
#include <map>
#include <memory>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <openssl/bio.h>
#include <snet/address.hpp>
#include <snet/event_data.hpp>
#include <snet/event/epoll.hpp>
#include <snet/tls/settings.hpp>

class EventManager
{
  public:
    static constexpr int kMaxEvents = 32;
    using EpollEvent = struct epoll_event;
    using EpollEventArray = std::array<EpollEvent, kMaxEvents>;

    EventManager(std::unique_ptr<AcceptSocket>&& sock,
                 snet::tls::ServerSettings& ctx)
        : epoll_()
        , listener_(std::move(sock))
        , ctx_(ctx)
    {
        epoll_.add(listener_->GetFd(), EPOLLIN);
    }

    ~EventManager()
    {
    }

    std::uint32_t OnConnected()
    {
        return EPOLLIN;
    }

    std::array<char, 1024> buffer;
    int readed = 0;

    std::uint32_t OnHandshake(std::unique_ptr<EventData>& evtData)
    {
        int ret = evtData->GetSslSocket().Accept();
        if (ret == 1)
        {
            return EPOLLIN;
        }

        int err = evtData->GetSslSocket().GetError(ret);
        if (err == SSL_ERROR_WANT_WRITE)
        {
            return EPOLLOUT;
        }
        else if (err == SSL_ERROR_WANT_READ)
        {
            ERR_print_errors_fp(stderr);
            return EPOLLIN;
        }
        ERR_print_errors_fp(stderr);
        return 0;
    }

    std::uint32_t OnReceive(std::unique_ptr<EventData>& evtData)
    {
        if (!evtData->GetSslSocket().HandshakeDone())
        {
            return OnHandshake(evtData);
        }
        readed = evtData->GetSslSocket().read(buffer.data(), sizeof(buffer));
        if (readed == 0)
        {
            return 0;
        }
        else if (readed < 0)
        {
            if (BIO_sock_should_retry(readed))
            {
                return EPOLLIN;
            }
            if (errno == ECONNRESET)
            {
                return 0;
            }
            throw std::runtime_error("read process error");
        }
        std::copy(std::begin(buffer), buffer.data() + readed,
                  std::ostream_iterator<char>(std::cout));
        return EPOLLOUT;
    }

    std::uint32_t OnSend(std::unique_ptr<EventData>& evtData)
    {
        auto ret = evtData->GetSslSocket().Write(buffer.data(), readed);
        if (ret == 0)
        {
            return 0;
        }
        else if (ret < 0)
        {
            if (BIO_sock_should_retry(ret))
            {
                return EPOLLOUT;
            }
            else
            {
                throw std::runtime_error("read process error");
            }
        }
        return EPOLLIN;
    }

    void MainThread(int timeout)
    {
        while (true)
        {
            EpollEventArray events;
            std::error_code ec;
            auto nReady = epoll_.wait(events.data(), kMaxEvents, timeout, ec);
            if (nReady < 0)
            {
                if (ec != std::errc::interrupted)
                {
                    std::cout << "Epoll error: " << ec.message();
                }
                continue;
            }
            for (auto i = 0; i < nReady; ++i)
            {
                auto flags = events.at(i).events;
                auto fd = events.at(i).data.fd;

                if (listener_->GetFd() == fd)
                {
                    Address addr;
                    auto asock = listener_->Accept(addr);
                    if (asock < 0)
                    {
                        if (BIO_sock_should_retry(asock))
                        {
                            continue;
                        }
                        else
                        {
                            throw std::runtime_error("accept() error");
                        }
                    }
                    else
                    {
                        std::cout << "socket " << asock
                                  << " opened: " << addr.ToString()
                                  << std::endl;
                        std::uint32_t events = OnConnected();
                        auto pasock = std::make_unique<Socket>(asock);
                        fds_[asock] = std::make_unique<EventData>(
                            std::move(pasock), ctx_);
                        epoll_.add(asock, events);
                    }
                }
                else
                {
                    auto& evtData = fds_.at(fd);
                    if (flags & EPOLLIN)
                    {
                        std::uint32_t events = OnReceive(evtData);
                        if (events == 0)
                        {
                            std::cout << "socket " << fd << " closed"
                                      << std::endl;
                            epoll_.del(fd);
                            fds_.erase(fd);
                        }
                        else
                        {
                            epoll_.modify(fd, events);
                        }
                    }
                    else if (flags & EPOLLOUT)
                    {
                        std::uint32_t events = OnSend(evtData);
                        if (events == 0)
                        {
                            std::cout << "socket " << fd << " closing\n ";
                            epoll_.del(fd);
                            fds_.erase(fd);
                        }
                        else
                        {
                            epoll_.modify(fd, events);
                        }
                    }
                }
            }
        }
    }

  private:
    snet::event::Epoll epoll_;
    std::unique_ptr<AcceptSocket> listener_;
    snet::tls::ServerSettings ctx_;

    std::map<int, std::unique_ptr<EventData>> fds_;
};
