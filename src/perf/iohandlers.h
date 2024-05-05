#pragma once

#include "defs.h"
#include "common.h"

void print_addresses(const fds_data *data, int &list_count);

//==============================================================================
class IoHandler {
public:
    IoHandler(int _fd_min, int _fd_max, int _fd_num, int _look_start, int _look_end);
    virtual ~IoHandler();

    inline int get_look_start() const { return m_look_start; }
    inline int get_look_end() const { return m_look_end; }

    virtual int prepareNetwork() = 0;
    void warmup(snet::perf::Message *pMsgRequest) const;

    const int m_fd_min, m_fd_max, m_fd_num;

protected:
    int m_look_start;
    int m_look_end; // non const because of epoll
};

//==============================================================================
class IoRecvfrom : public IoHandler {
public:
    IoRecvfrom(int _fd_min, int _fd_max, int _fd_num);
    virtual ~IoRecvfrom();

    inline void update() {}
    inline int waitArrival() { return (m_fd_num); }
    inline int analyzeArrival(int ifd) const {
        assert(g_fds_array[ifd] && "invalid fd");

        int active_fd_count = g_fds_array[ifd]->active_fd_count;
        int *active_fd_list = g_fds_array[ifd]->active_fd_list;

        assert(active_fd_list && "corrupted fds_data object");

        return (active_fd_count ? active_fd_list[0] : ifd);
    }

    virtual int prepareNetwork();
};

