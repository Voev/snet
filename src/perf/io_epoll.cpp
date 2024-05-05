#include "io_epoll.hpp"

IoEpoll::IoEpoll(int _fd_min, int _fd_max, int _fd_num)
    : IoHandler(_fd_min, _fd_max, _fd_num, 0, 0)
    , timeout_(-1)
{
}

IoEpoll::~IoEpoll()
{
}

void IoEpoll::update()
{
    int ifd = 0;

    m_look_start = 0;
    m_look_end = m_fd_num;
    m_max_events = m_fd_num;
    for (ifd = m_fd_min; ifd <= m_fd_max; ifd++)
    {
        if (g_fds_array[ifd])
        {
            int i = 0;
            int active_fd_count = g_fds_array[ifd]->active_fd_count;
            int* active_fd_list = g_fds_array[ifd]->active_fd_list;

            assert(active_fd_list && "corrupted fds_data object");

            while (active_fd_count)
            {
                /* process active sockets in case TCP (listen sockets are set in
                 * prepareNetwork()) and
                 * skip active socket in case UDP (it is the same with set in
                 * prepareNetwork())
                 */
                if (active_fd_list[i] != (int)INVALID_SOCKET)
                {
                    if (active_fd_list[i] != ifd)
                    {
                        epoll_.add(active_fd_list[i], EPOLLIN | EPOLLPRI);

                        /* it is possible to set the same socket
                         * EEXIST error appears in this case but it harmless
                         * condition
                         */
                        errno = 0;

                        m_max_events++;
                    }
                    active_fd_count--;
                }
                i++;

                assert((i < MAX_ACTIVE_FD_NUM) &&
                       "maximum number of active connection to the single TCP "
                       "addr:port");
                assert(m_max_events < max_fds_num);
            }
        }
    }
    /* It can be omitted */
    m_look_end = m_max_events;
}

//------------------------------------------------------------------------------
int IoEpoll::prepareNetwork()
{
    int rc = SOCKPERF_ERR_NONE;

    events_.resize(max_fds_num);

        for (int ifd = m_fd_min; ifd <= m_fd_max; ifd++)
        {
            if (g_fds_array[ifd])
            {
                epoll_.add(ifd, EPOLLIN | EPOLLPRI);
                m_max_events++;
            }
        }
    }

    return 0;
}

int IoEpoll::waitArrival()
{
    m_look_end = epoll_.wait(events_.data(), events_.size(), timeout_);
    return m_look_end;
}

int IoEpoll::analyzeArrival(int ifd) const
{
    return events_[ifd].data.fd;
}