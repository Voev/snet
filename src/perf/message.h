#pragma once
#include <exception>
#include <stdexcept>
#include <cassert>
#include <stdint.h> // for uint64_t
#include <snet/utils/noncopyable.hpp>
#include "os_abstract.h"

namespace snet::perf
{

// Using pack() pragma set needed alignment
#pragma pack(push, 2)
class MsgHeader
{
    friend class Message;

public:
    MsgHeader(uint64_t _sequence_number = 0)
        : m_sequence_number(_sequence_number)
    {
    }
    ~MsgHeader()
    {
    }

    bool isClient() const
    {
        return (!!(m_flags_and_length.m_flags & MASK_CLIENT));
    }
    void setClient()
    {
        m_flags_and_length.m_flags |= MASK_CLIENT;
    }
    void setServer()
    {
        m_flags_and_length.m_flags &= ~MASK_CLIENT;
    }

    bool isPongRequest() const
    {
        return (!!(m_flags_and_length.m_flags & MASK_PONG));
    }
    void setPongRequest()
    {
        m_flags_and_length.m_flags |= MASK_PONG;
    }
    void resetPongRequest()
    {
        m_flags_and_length.m_flags &= ~MASK_PONG;
    }

    bool isWarmupMessage() const
    {
        return (!!(m_flags_and_length.m_flags & MASK_WARMUP_MSG));
    }
    void setWarmupMessage()
    {
        m_flags_and_length.m_flags |= MASK_WARMUP_MSG;
    }
    void resetWarmupMessage()
    {
        m_flags_and_length.m_flags &= ~MASK_WARMUP_MSG;
    }

    void hton()
    {
        m_sequence_number = htonll(m_sequence_number);
        m_flags_and_length.m_flags = htons(m_flags_and_length.m_flags);
        m_flags_and_length.length = htonl(m_flags_and_length.length);
    }

    void ntoh()
    {
        m_sequence_number = ntohll(m_sequence_number);
        m_flags_and_length.m_flags = ntohs(m_flags_and_length.m_flags);
        m_flags_and_length.length = ntohl(m_flags_and_length.length);
    }
    // this is different than sizeof(MsgHeader) and safe only for the current
    // implementation of the class
    static constexpr int EFFECTIVE_SIZE =
        (int)(sizeof(uint64_t) + sizeof(uint16_t) + sizeof(uint32_t));
    //	static const int EFFECTIVE_SIZE = 16;

private:
    typedef struct
    {
        uint16_t m_flags;
        uint32_t length;
    } s_flags_and_length;
    // NOTE: m_sequence_number must be the 1st field, because we want
    // EFFECTIVE_SIZE of header to be 14 bytes hence we need the padding (to 16
    // bytes) to be after last field and not between fields pack() pragma can be
    // added to set needed alignment
    uint64_t m_sequence_number;
    s_flags_and_length m_flags_and_length;

    static const uint32_t MASK_CLIENT = 1;
    static const uint32_t MASK_PONG = 2;
    static const uint32_t MASK_WARMUP_MSG = 4;
};
#pragma pack(pop)

class Message : public utils::NonCopyable
{
public:
    Message();
    ~Message();

    static void initMaxSize(int size);
    static void initMaxSeqNo(uint64_t seqno);
    static size_t getMaxSize()
    {
        return ms_maxSize;
    }

    uint8_t* getBuf() const
    {
        return m_addr;
    }
    uint8_t* setBuf(uint8_t* addr = nullptr)
    {

        /* set buffer as intrenal in case NULL is passed */
        if (!addr)
        {
            int alignment = (8 - reinterpret_cast<intptr_t>(m_buf)) % 8;
            addr = (uint8_t*)m_buf +
                   alignment; // this will force m_sequence_number to be 8
                              // aligned even on 32 bit arch
        }

        m_addr = addr;
        m_header = (MsgHeader*)m_addr;
        m_data = (uint8_t*)m_header + MsgHeader::EFFECTIVE_SIZE;

        if ((void*)m_addr != (void*)m_header)
            throw std::logic_error("address error");

        return m_addr;
    }

    const MsgHeader* getHeader() const
    {
        return m_header;
    }
    MsgHeader* getHeader()
    {
        return m_header;
    }
    uint8_t* getData() const
    {
        return m_data;
    }

    uint16_t isClient() const
    {
        return m_header->isClient();
    }
    void setClient()
    {
        m_header->setClient();
    }
    void setServer()
    {
        m_header->setServer();
    }

    uint16_t isPongRequest() const
    {
        return m_header->isPongRequest();
    }

    uint64_t getSequenceCounter() const
    {
        assert((m_header->m_sequence_number <= ms_maxSequenceNo) &&
               "exceeded message number limitation");
        return m_header->m_sequence_number;
    }
    void setSequenceCounter(uint64_t _sequence)
    {
        assert((_sequence <= ms_maxSequenceNo) &&
               "exceeded message number limitation");
        m_header->m_sequence_number = _sequence;
    }
    void incSequenceCounter()
    {
        m_header->m_sequence_number++;
    }
    void decSequenceCounter()
    {
        m_header->m_sequence_number--;
    }

    uint16_t isWarmupMessage() const
    {
        return m_header->isWarmupMessage();
    }
    void setWarmupMessage()
    {
        m_header->setWarmupMessage();
    }
    void resetWarmupMessage()
    {
        m_header->resetWarmupMessage();
    }

    void setHeaderToHost()
    {
        m_header->ntoh();
    }
    void setHeaderToNetwork()
    {
        m_header->hton();
    }

    uint16_t getFlags() const
    {
        return (m_header->m_flags_and_length.m_flags);
    }

    int getLength() const
    {
        // extract msg length from m_length and m_flags.
        return m_header->m_flags_and_length.length;
    }
    void setLength(uint32_t _length)
    {
        m_header->m_flags_and_length.length = _length;
    }

    bool isValidHeader() const
    {
        return (unsigned)getLength() <= (unsigned)ms_maxSize;
    }

private:
    uint8_t* m_buf;

    uint8_t* m_addr;     // points to 1st 8 aligned adrs inside m_buf
    MsgHeader* m_header; // points to header
    uint8_t* m_data;     // points to data

    static uint64_t ms_maxSequenceNo; // maximum expected sequence number
    static int ms_maxSize; // use int (instead of size_t to save casting to
                           // 'int' in recvfrom)
};

} // namespace snet::perf