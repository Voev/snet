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

#include <snet/log/logger.hpp>
#include "iohandlers.h"

using namespace snet;

IoHandler::IoHandler(int _fd_min, int _fd_max, int _fd_num, int _look_start,
                     int _look_end)
    : m_fd_min(_fd_min)
    , m_fd_max(_fd_max)
    , m_fd_num(_fd_num)
    , m_look_start(_look_start)
    , m_look_end(_look_end)
{
}

IoHandler::~IoHandler()
{
}

//------------------------------------------------------------------------------
void IoHandler::warmup(snet::perf::Message* pMsgRequest) const
{
    if (!g_pApp->m_const_params.do_warmup)
        return;
    pMsgRequest->setWarmupMessage();

    log::info("Warmup stage (sending a few dummy messages)...");
    for (int ifd = m_fd_min; ifd <= m_fd_max; ifd++)
    {
        fds_data* data = g_fds_array[ifd];
        if (data && data->is_multicast)
        {
            for (int count = 0; count < 2; count++)
            {
                int length = pMsgRequest->getLength();
                pMsgRequest->setHeaderToNetwork();
                msg_sendto(ifd, pMsgRequest->getBuf(), length,
                           data->server_addr);
                pMsgRequest->setHeaderToHost();
            }
        }
    }
    pMsgRequest->resetWarmupMessage();
}
