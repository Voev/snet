/*
 * Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

#ifndef INPUT_HANDLERS_H_
#define INPUT_HANDLERS_H_

#include "message_parser.h"

namespace snet::perf
{

class RecvFromInputHandler : public MessageParser<InPlaceAccumulation>
{
private:
    SocketRecvData& m_recv_data;
    uint8_t* m_actual_buf;
    int m_actual_buf_size;

public:
    inline RecvFromInputHandler(snet::perf::Message* msg,
                                SocketRecvData& recv_data)
        : MessageParser<InPlaceAccumulation>(msg)
        , m_recv_data(recv_data)
        , m_actual_buf_size(0)
    {
    }

    /** Receive pending data from a socket
     * @param [in] socket descriptor
     * @param [out] recvfrom_addr address to save peer address into
     * @param [inout] in - storage size, out - actual address size
     * @return status code
     */
    inline int receive_pending_data(int fd, network::Endpoint& addr)
    {
        int ret = 0;
        int flags = 0;
        uint8_t* buf = m_recv_data.cur_addr + m_recv_data.cur_offset;

/*
    When writing onto a connection-oriented socket that has been shut down
    (by the local or the remote end) SIGPIPE is sent to the writing process
    and EPIPE is returned. The signal is not sent when the write call specified
    the MSG_NOSIGNAL flag.
    Note: another way is call signal (SIGPIPE,SIG_IGN);
 */
#ifndef __windows__
        flags = MSG_NOSIGNAL;
#endif

        if (g_fds_array[fd]->tls_handle)
        {
            ret = tls_read(g_fds_array[fd]->tls_handle, buf,
                           m_recv_data.cur_size);
        }
        else
        {
            network::socket_length_type len;
            ret = recvfrom(fd, buf, m_recv_data.cur_size, flags,
                           addr.data(), &len);
        }
        m_actual_buf = buf;
        m_actual_buf_size = ret;

#if defined(LOG_TRACE_MSG_IN) && (LOG_TRACE_MSG_IN == TRUE)
        printf(">   ");
        hexdump(buf, MsgHeader::EFFECTIVE_SIZE);
#endif /* LOG_TRACE_MSG_IN */

#if defined(LOG_TRACE_RECV) && (LOG_TRACE_RECV == TRUE)
        std::string hostport = sockaddr_to_hostport(recvfrom_addr);
        LOG_TRACE("raw", "%s IP: %s [fd=%d ret=%d] %s", __FUNCTION__,
                  hostport.c_str(), fd, ret, strerror(errno));
#endif /* LOG_TRACE_RECV */

        if (ret == 0 || errno == EPIPE || os_err_conn_reset())
        {
            /* If no messages are available to be received and the peer has
             * performed an orderly shutdown, recv()/recvfrom() shall return 0
             * */
            ret = RET_SOCKET_SHUTDOWN;
            errno = 0;
        }
        /* ret < MsgHeader::EFFECTIVE_SIZE
         * ret value less than MsgHeader::EFFECTIVE_SIZE
         * is bad case for UDP so error could be actual but it is possible value
         * for TCP
         */
        else if (ret < 0 && !os_err_eagain() && errno != EINTR)
        {
            recvfromError(fd);
        }

        return ret;
    }

    template <class Callback>
    inline bool iterate_over_buffers(Callback& callback)
    {
        return process_buffer(callback, m_recv_data, m_actual_buf,
                              m_actual_buf_size);
    }

    inline void cleanup()
    {
    }
};

template <class InputHandler, class IoType> struct input_handler_helper
{
    inline static InputHandler create_input_handler(snet::perf::Message* msg,
                                                    SocketRecvData& recv,
                                                    IoType& ioHandler)
    {
        (void)ioHandler;
        return InputHandler(msg, recv);
    }
};

} // namespace snet::perf
#endif // INPUT_HANDLERS_H_