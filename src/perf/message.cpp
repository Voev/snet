
#include "message.h"
#include <string>
#include "common.h"

namespace snet::perf
{

// static memebers initialization
/*static*/ uint64_t Message::ms_maxSequenceNo;
/*static*/ int Message::ms_maxSize;

/*static*/ void Message::initMaxSize(int size)
{
    if (size < 0)
        throw std::out_of_range("size < 0");
    else if (ms_maxSize)
        throw std::logic_error("MaxSize is already initialized");
    else
        ms_maxSize = size;
}

//------------------------------------------------------------------------------
/*static*/ void Message::initMaxSeqNo(uint64_t seqno)
{
    if (ms_maxSequenceNo)
        throw std::logic_error("MaxSeqNo is already initialized");
    else
        ms_maxSequenceNo = seqno;
}

//------------------------------------------------------------------------------
Message::Message()
{
    if (!ms_maxSize)
        throw std::logic_error("MaxSize was NOT initialized");

    if (ms_maxSize < MsgHeader::EFFECTIVE_SIZE)
        throw std::out_of_range("maxSize < MsgHeader::EFFECTIVE_SIZE");

    m_buf = new uint8_t[ms_maxSize + 7]; // extra +7 for enabling 8 alignment of
                                         // m_sequence_number
    setBuf();

    for (int len = 0; len < ms_maxSize; len++)
        m_addr[len] = (uint8_t)rand();
    memset((void*)m_header, 0, MsgHeader::EFFECTIVE_SIZE);
}

Message::~Message()
{
    delete[] m_buf;
}

} // namespace snet::perf