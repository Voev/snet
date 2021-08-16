#pragma once
#include <array>
#include <map>
#include <memory>
#include <cstdint>
#include <cstring>
#include <openssl/bio.h>

#include <snet/address.hpp>
#include <snet/event_poll.hpp>
#include <snet/event_data.hpp>

class EventManager
{
  public:
    static constexpr int kMaxEvents = 32;
    using EpollEvent = struct epoll_event;
    using EpollEventArray = std::array<EpollEvent, kMaxEvents>;

    EventManager(std::unique_ptr<AcceptSocket>&& sock)
        : epoll_(std::make_unique<Epoll>())
        , listener_(std::move(sock))
    {
        epoll_->Add(listener_->GetFd(), EPOLLIN);
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

    std::uint32_t OnReceive(const std::unique_ptr<Socket>& sock)
    {
        readed = sock->Read(buffer.data(), sizeof(buffer));
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
            else
            {
                throw std::runtime_error("read process error");
            }
        }
        std::copy(std::begin(buffer), buffer.data() + readed,
                  std::ostream_iterator<char>(std::cout));
        return EPOLLOUT;
    }

    std::uint32_t OnSend(const std::unique_ptr<Socket>& sock)
    {
        auto ret = sock->Write(buffer.data(), readed);
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
            auto nReady = epoll_->Wait(events.data(), kMaxEvents, timeout);
            if (nReady < 0)
            {
                if (errno != EINTR)
                {
                    std::cout << "Epoll error: " << errno << " fd is <todo>";
                }
                continue;
            }
            for (auto i = 0; i < nReady; ++i)
            {
                auto flags = events.at(i).events;
                auto fd = events.at(i).data.fd;

                if (flags & EPOLLERR)
                {
                    std::cout << "epoll_wait returned EPOLLERR" << std::endl;
                    return;
                }

                if (listener_->GetFd() == fd)
                {
                    Address addr;
                    int asock = listener_->Accept(addr);
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
                        std::cout << addr.ToString() << std::endl;
                        std::uint32_t events = OnConnected();
                        fds_[asock] = std::make_unique<Socket>(asock);
                        epoll_->Add(asock, events);
                    }
                }
                else
                {
                    auto& sock = fds_.at(fd);
                    if (flags & EPOLLIN)
                    {
                        std::uint32_t events = OnReceive(sock);
                        if (events == 0)
                        {
                            std::cout << "socket " << fd << " closing\n ";
                            epoll_->Delete(fd);
                            fds_.erase(fd);
                        }
                        else
                        {
                            epoll_->Modify(fd, events);
                        }
                    }
                    else if (flags & EPOLLOUT)
                    {
                        std::uint32_t events = OnSend(sock);
                        if (events == 0)
                        {
                            std::cout << "socket " << fd << " closing\n ";
                            epoll_->Delete(fd);
                            fds_.erase(fd);
                        }
                        else
                        {
                            epoll_->Modify(fd, events);
                        }
                    }
                }
            }
        }
    }

  private:
    std::unique_ptr<Epoll> epoll_;
    std::unique_ptr<AcceptSocket> listener_;
    std::map<int, std::unique_ptr<Socket>> fds_;
};
