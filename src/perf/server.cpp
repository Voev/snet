/*
 * Copyright (c) 2011-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the Mellanox Technologies Ltd nor the names of its
 *    contributors may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
 * EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "server.h"
#include "iohandlers.h"
#include <memory>
#include <vector>
#include <thread>
#include <snet/log/logger.hpp>
#include <snet/network/socket_utils.hpp>

namespace snet::perf
{

// static members initialization
/*static*/ seq_num_map SwitchOnCalcGaps::ms_seq_num_map;
static std::vector<std::thread::native_handle_type> thread_array;

//==============================================================================

//------------------------------------------------------------------------------
ServerBase::ServerBase(IoHandler& _ioHandler)
    : m_ioHandlerRef(_ioHandler)
{
    m_pMsgReply = new Message();
    m_pMsgReply->setLength(MAX_PAYLOAD_SIZE);

    m_pMsgRequest = new Message();
    m_pMsgRequest->getHeader()->setServer();
    m_pMsgRequest->setLength(g_pApp->m_const_params.msg_size);
}

//------------------------------------------------------------------------------
ServerBase::~ServerBase()
{
    delete m_pMsgReply;
    delete m_pMsgRequest;
}

//------------------------------------------------------------------------------
int ServerBase::initBeforeLoop()
{
    int rc = SOCKPERF_ERR_NONE;

    rc = set_affinity_list(os_getthread(),
                           g_pApp->m_const_params.threads_affinity);

    if (g_b_exit)
        return rc;

    /* bind socket */
    if (rc == SOCKPERF_ERR_NONE)
    {
        snet::log::debug("thread %lu: fd_min: %d, fd_max : %d, fd_num: %d",
                         (unsigned long)os_getthread().tid,
                         m_ioHandlerRef.m_fd_min, m_ioHandlerRef.m_fd_max,
                         m_ioHandlerRef.m_fd_num);

        // cycle through all set fds in the array (with wrap around to
        // beginning)
        for (int ifd = m_ioHandlerRef.m_fd_min; ifd <= m_ioHandlerRef.m_fd_max;
             ifd++)
        {

            if (!(g_fds_array[ifd] && (g_fds_array[ifd]->active_fd_list)))
                continue;
#ifdef USING_EXTRA_API // callback-extra-api Only
            g_fds_array[ifd]->p_msg = m_pMsgReply;
#endif // USING_EXTRA_API
            snet::network::Endpoint& p_bind_addr = g_fds_array[ifd]->server_addr;
            snet::log::debug("[fd=%d] Binding to: %s...", ifd,
                             p_bind_addr.toString());
            if (bind(ifd, p_bind_addr.data(),
                     p_bind_addr.size()) < 0)
            {
                snet::log::error("[fd=%d] Can`t bind socket, IP to bind: %s\n", ifd,
                        p_bind_addr.toString());
                rc = SOCKPERF_ERR_SOCKET;
                break;
            }
            /*
             * since when using VMA there is no qp until the bind, and vma
             * cannot check that rate-limit is supported this is done here and
             * not with the rest of the setsockopt
             */
            if (s_user_params.rate_limit > 0 &&
                sock_set_rate_limit(ifd, s_user_params.rate_limit))
            {
                snet::log::error("[fd=%d] failed setting rate limit, %s\n", ifd,
                        p_bind_addr.toString());
                rc = SOCKPERF_ERR_SOCKET;
                break;
            }

            if ((g_fds_array[ifd]->sock_type == SOCK_STREAM) &&
                (listen(ifd, 10) < 0))
            {
                snet::log::error("Failed listen() for connection\n");
                rc = SOCKPERF_ERR_SOCKET;
                break;
            }
        }
    }

    if (g_b_exit)
        return rc;

    if (rc == SOCKPERF_ERR_NONE)
    {
        {
            printf(MODULE_NAME ": [SERVER] listen on:");
        }

        rc = m_ioHandlerRef.prepareNetwork();
        if (rc == SOCKPERF_ERR_NONE)
        {
            sleep(g_pApp->m_const_params.pre_warmup_wait);
            m_ioHandlerRef.warmup(m_pMsgRequest);
            snet::log::info("[tid %lu] using %s() to block on socket(s)",
                    (unsigned long)os_getthread().tid,
                    handler2str(g_pApp->m_const_params.fd_handler_type));
        }
    }

    return rc;
}

//------------------------------------------------------------------------------
void ServerBase::cleanupAfterLoop()
{
    // cleanup
    snet::log::debug("thread %lu released allocations",
                     (unsigned long)os_getthread().tid);

    if (!g_pApp->m_const_params.mthread_server)
    {
        snet::log::info("%s() exit", __func__);
    }
}

//==============================================================================
//==============================================================================

//------------------------------------------------------------------------------
template <class IoType, class SwitchCalcGaps>
Server<IoType, SwitchCalcGaps>::Server(int _fd_min, int _fd_max, int _fd_num)
    : ServerBase(m_ioHandler)
    , m_ioHandler(_fd_min, _fd_max, _fd_num)
{
}

//------------------------------------------------------------------------------
template <class IoType, class SwitchCalcGaps>
Server<IoType, SwitchCalcGaps>::~Server()
{
}

//------------------------------------------------------------------------------
template <class IoType, class SwitchCalcGaps>
void Server<IoType, SwitchCalcGaps>::doLoop()
{
    int numReady = 0;
    int actual_fd = 0;

    while (!g_b_exit)
    {
        // wait for arrival
        numReady = m_ioHandler.waitArrival();

        // check errors
        if (g_b_exit)
            continue;
        if (numReady < 0)
        {
            snet::log::error("%s()",
                    handler2str(g_pApp->m_const_params.fd_handler_type));
            exit_with_log(SOCKPERF_ERR_FATAL);
        }
        if (numReady == 0)
        {
            if (!g_pApp->m_const_params.select_timeout)
                snet::log::info("Error: %s() returned without fd ready",
                        handler2str(g_pApp->m_const_params.fd_handler_type));
            continue;
        }

        // handle arrival and response
        int accept_fd = (int)INVALID_SOCKET; // TODO: use SOCKET all over the
                                             // way and avoid this cast
        bool do_update = false;
        for (int ifd = m_ioHandler.get_look_start();
             (numReady) && (ifd < m_ioHandler.get_look_end()); ifd++)
        {
            actual_fd = m_ioHandler.analyzeArrival(ifd);

            if (actual_fd)
            {
                assert(g_fds_array[actual_fd] && "invalid fd");

                if (!g_fds_array[actual_fd])
                {
                    /* do nothing invalid fd*/
                }
                else
                {
                    accept_fd = server_accept(actual_fd);
                    if (accept_fd == actual_fd)
                    {
                        int m_recived =
                            g_pApp->m_const_params.max_looping_over_recv;
                        while ((0 != m_recived) && (!g_b_exit))
                        {
                            if (m_recived > 0)
                            {
                                m_recived--;
                            }
                            if (server_receive_then_send(actual_fd))
                            {
                                do_update = true;
                            }
                            else if (os_err_eagain())
                            {
                                break;
                            }
                        }
                    }
                    else if (accept_fd != (int)INVALID_SOCKET)
                    { // TODO: use SOCKET all over the
                      // way and avoid this cast
                        do_update = true;
                    }
                    else
                    {
                        /* do nothing */
                    }
                }
                numReady--;
            }
        }

        /* do update of active fd in case accept/close was occured */
        if (do_update)
        {
            m_ioHandler.update();
        }

        assert(!numReady &&
               "all waiting descriptors should have been processed");
    }
}

//------------------------------------------------------------------------------
template <class IoType, class SwitchCalcGaps>
int Server<IoType, SwitchCalcGaps>::server_accept(int ifd)
{
    bool do_accept = false;
    int active_ifd = ifd;

    if (!g_fds_array[ifd])
    {
        return (int)INVALID_SOCKET; // TODO: use SOCKET all over the way and
                                    // avoid this cast
    }
    if (g_fds_array[ifd]->sock_type == SOCK_STREAM &&
        g_fds_array[ifd]->active_fd_list)
    {
        std::unique_ptr<fds_data> tmp{new fds_data};

        if (!tmp)
        {
            snet::log::error("Failed to allocate memory with malloc()");
            return (int)INVALID_SOCKET; // TODO: use SOCKET all over the way and
                                        // avoid this cast
        }
        *tmp = *g_fds_array[ifd];
        tmp->recv.buf =
            (uint8_t*)MALLOC(sizeof(uint8_t) * 2 * MAX_PAYLOAD_SIZE);
        if (!tmp->recv.buf)
        {
            snet::log::error("Failed to allocate memory with malloc()");
            return SOCKPERF_ERR_NO_MEMORY;
        }
        tmp->next_fd = ifd;
        tmp->active_fd_list = NULL;
        tmp->active_fd_count = 0;
        tmp->recv.cur_addr = tmp->recv.buf;
        tmp->recv.max_size = MAX_PAYLOAD_SIZE;
        tmp->recv.cur_offset = 0;
        tmp->recv.cur_size = tmp->recv.max_size;

        // TODO: use SOCKET all over the way and avoid this cast

        snet::network::socket_addr_type addr;
        snet::network::socket_length_type addrlen;
        std::error_code ec;
        active_ifd = snet::network::accept(ifd, &addr, &addrlen, ec);

        if (active_ifd < 0)
        {
            active_ifd = (int)INVALID_SOCKET; // TODO: use SOCKET all over the
                                              // way and avoid this cast
            if (tmp->recv.buf)
            {
                FREE(tmp->recv.buf);
            }
            if (tmp->active_fd_list)
            {
                FREE(tmp->active_fd_list);
            }
            snet::log::debug("Can`t accept connection");
        }
        else
        {
            /* Check if it is exceeded internal limitations
             * max_fds_num and MAX_ACTIVE_FD_NUM
             */
            if ((active_ifd < max_fds_num) &&
                (g_fds_array[ifd]->active_fd_count < (MAX_ACTIVE_FD_NUM - 1)))
            {
                if (prepare_socket(active_ifd, tmp.get()) !=
                    (int)INVALID_SOCKET)
                { // TODO: use SOCKET all over the way and avoid this cast
                    int* active_fd_list = g_fds_array[ifd]->active_fd_list;
                    int i = 0;

                    for (i = 0; i < MAX_ACTIVE_FD_NUM; i++)
                    {
                        if (active_fd_list[i] == (int)INVALID_SOCKET)
                        { // TODO: use SOCKET all over
                          // the way and avoid this
                          // cast
                            active_fd_list[i] = active_ifd;
                            g_fds_array[ifd]->active_fd_count++;
                            g_fds_array[active_ifd] = tmp.release();

                            //snet::log::debug("peer address to accept: {} [{}]",
                            //                 addr.toString(), active_ifd);
#if defined(DEFINED_TLS)
                            if (g_pApp->m_const_params.tls)
                            {
                                g_fds_array[active_ifd]->tls_handle =
                                    tls_establish(active_ifd);
                                if (!g_fds_array[active_ifd]->tls_handle)
                                {
                                    break;
                                }
                            }
#endif /* DEFINED_TLS */
                            do_accept = true;
                            break;
                        }
                    }
                }
            }

            if (!do_accept)
            {
                snet::log::info("WARNING: closing a socket because we can not accept "
                        "active_fd_count=%d MAX_ACTIVE_FD_NUM=%d",
                        g_fds_array[ifd]->active_fd_count, MAX_ACTIVE_FD_NUM);
                close(active_ifd);
                active_ifd = (int)INVALID_SOCKET; // TODO: use SOCKET all over
                                                  // the way and avoid this cast
                if (tmp->recv.buf)
                {
                    FREE(tmp->recv.buf);
                }
                if (tmp->active_fd_list)
                {
                    FREE(tmp->active_fd_list);
                }

                //snet::log::debug("peer address to refuse: %s [%d]",
                //                 addr.toString(), active_ifd);
            }
        }
    }

    return active_ifd;
}

//------------------------------------------------------------------------------
template <class IoType, class SwitchCheckGaps>
void server_handler(int _fd_min, int _fd_max, int _fd_num)
{
    Server<IoType, SwitchCheckGaps> s(_fd_min, _fd_max, _fd_num);
    s.doHandler();
}

//------------------------------------------------------------------------------
template <class IoType>
void server_handler(int _fd_min, int _fd_max, int _fd_num)
{
    if (g_pApp->m_const_params.b_server_detect_gaps)
        server_handler<IoType, SwitchOnCalcGaps>(_fd_min, _fd_max, _fd_num);
    else
        server_handler<IoType, SwitchOff>(_fd_min, _fd_max, _fd_num);
}

//------------------------------------------------------------------------------
void server_handler(handler_info* p_info)
{
    if (p_info)
    {
        switch (g_pApp->m_const_params.fd_handler_type)
        {
        case RECVFROM:
        {
            server_handler<IoRecvfrom>(p_info->fd_min, p_info->fd_max,
                                       p_info->fd_num);
            break;
        }
        case RECVFROMMUX:
        {
            server_handler<IoRecvfromMUX>(p_info->fd_min, p_info->fd_max,
                                          p_info->fd_num);
            break;
        }
        case SELECT:
        {
            server_handler<IoSelect>(p_info->fd_min, p_info->fd_max,
                                     p_info->fd_num);
            break;
        }
#ifndef __windows__
        case POLL:
        {
            server_handler<IoPoll>(p_info->fd_min, p_info->fd_max,
                                   p_info->fd_num);
            break;
        }
#if !defined(__FreeBSD__) && !defined(__APPLE__)
        case EPOLL:
        {
            server_handler<IoEpoll>(p_info->fd_min, p_info->fd_max,
                                    p_info->fd_num);
            break;
        }
#endif // !defined(__FreeBSD__) && !defined(__APPLE__)
#if defined(__FreeBSD__) || defined(__APPLE__)
        case KQUEUE:
        {
            server_handler<IoKqueue>(p_info->fd_min, p_info->fd_max,
                                     p_info->fd_num);
            break;
        }
#endif // defined(__FreeBSD__) || defined(__APPLE__)
#endif
        default:
            snet::log::error("unknown file handler");
        }
    }
}

//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
void find_min_max_fds(int start_look_from, int len, int* p_fd_min,
                      int* p_fd_max)
{
    int num_of_detected_fds;
    int i;

    for (num_of_detected_fds = 0, i = start_look_from;
         num_of_detected_fds < len; i++)
    {
        if (g_fds_array[i])
        {
            if (!num_of_detected_fds)
            {
                *p_fd_min = i;
            }
            num_of_detected_fds++;
        }
    }
    *p_fd_max = i - 1;
}

//------------------------------------------------------------------------------
void server_sig_handler(int signum)
{
    if (g_b_exit)
    {
        snet::log::info("Test end (interrupted by signal %d)", signum);
        snet::log::debug("thread %lu - exiting",
                         (unsigned long)os_getthread().tid);
        return;
    }

    // Just in case not Activity updates where logged add a '\n'
    if (g_pApp->m_const_params.packetrate_stats_print_ratio &&
        !g_pApp->m_const_params.packetrate_stats_print_details &&
        (g_pApp->m_const_params.packetrate_stats_print_ratio < g_receiveCount))
        printf("\n");

    {
        switch (signum)
        {
        case SIGINT:
            snet::log::info("Test end (interrupted by user)");
            break;
        default:
            snet::log::info("Test end (interrupted by signal %d)", signum);
            break;
        }
    }

    if (!g_receiveCount)
    {
        snet::log::info("No messages were received on the server.");
    }
    else
    {
        snet::log::info("Total %" PRIu64 " messages received and handled",
                g_receiveCount); // TODO: print also send count
    }
    SwitchOnCalcGaps::print_summary();
    g_b_exit = true;
}

// Temp location because of compilation issue (inline-unit-growth=200) with the
// way this method was inlined
void SwitchOnCalcGaps::execute(snet::network::Endpoint& clt_addr, uint64_t seq_num,
                               bool is_warmup)
{
    seq_num_map::iterator itr = ms_seq_num_map.find(clt_addr);
    bool starting_new_session = false;
    bool print_summary = false;

    if (itr == ms_seq_num_map.end())
    {
        clt_session_info_t new_session;
        new_session.addr = clt_addr;
        new_session.seq_num = seq_num;
        new_session.total_drops = 0;
        new_session.started = false;
        std::pair<seq_num_map::iterator, bool> ret_val = ms_seq_num_map.insert(
            seq_num_map::value_type(clt_addr, new_session));
        if (ret_val.second)
            itr = ret_val.first;
        else
        {
            snet::log::error("Failed to insert new session info, so the gap detection "
                    "is not supported.");
            return;
        }
        starting_new_session = true;
    }
    else if (is_warmup && itr->second.started)
    {
        // first warmup packet and old session was found in DB =>
        // needed to print old session summary.
        itr->second.started = false;
        starting_new_session = true;
        print_summary = true;
    }

    // print summary of the previous session + reset the counters
    if (print_summary)
    {
        print_session_summary(&(itr->second));
        itr->second.seq_num = seq_num;
        itr->second.total_drops = 0;
    }

    // received first packet of the new session
    if (starting_new_session)
        print_new_session_info(&itr->second);

    if (!is_warmup)
    {
        if (!itr->second.started)
            itr->second.started = true;
        check_gaps(seq_num, itr);
    }
}

// Temp location because of compilation issue (inline-unit-growth=200) with the
// way this method was inlined
void SwitchOnActivityInfo::execute(uint64_t counter)
{
    static TicksTime s_currTicks;
    static int s_print_header = 0;

    if (counter % g_pApp->m_const_params.packetrate_stats_print_ratio == 0)
    {
        if (g_pApp->m_const_params.packetrate_stats_print_details)
        {
            TicksDuration interval = s_currTicks.setNow() - g_lastTicks;
            if (interval < TicksDuration::TICKS1HOUR)
            {
                if (s_print_header++ % 20 == 0)
                {
                    printf("    -- Interval --     -- Message Rate --  -- "
                           "Total Message Count --\n");
                }
                int64_t interval_packet_rate =
                    g_pApp->m_const_params.packetrate_stats_print_ratio *
                    NSEC_IN_SEC / interval.toNsec();
                printf(" %10" PRId64 " [usec]    %10" PRId64
                       " [msg/s]    %13" PRIu64 " [msg]\n",
                       interval.toUsec(), interval_packet_rate, counter);
            }
            g_lastTicks = s_currTicks;
        }
        else
        {
            printf(".");
        }
        fflush(stdout);
    }
}

} // namespace snet::perf