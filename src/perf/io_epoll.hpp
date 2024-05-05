#pragma once
#include <snet/event/epoll.hpp>
#include "iohandlers.h"

class IoEpoll : public IoHandler {
public:
    IoEpoll(int _fd_min, int _fd_max, int _fd_num);
    
    ~IoEpoll();

    int prepareNetwork();
    
    void update();

    int waitArrival();
    
    int analyzeArrival(int ifd) const;

private:
    std::vector<snet::event::Epoll::Event> events_;
    snet::event::Epoll epoll_;
    const int timeout_;
    int maxEvents_;
};
