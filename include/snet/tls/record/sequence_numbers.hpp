#pragma once
#include <cstdint>

class SequenceNumbers final
{
public:
    SequenceNumbers()
    {
        reset();
    }

    void reset()
    {
        writeSeqNumber_ = 0;
        readSeqNumber_ = 0;
        writeEpoch_ = 0;
        readEpoch_ = 0;
    }

    void newReadCipherState()
    {
        readSeqNumber_ = 0;
        readEpoch_++;
    }

    void newWriteCipherState()
    {
        writeSeqNumber_ = 0;
        writeEpoch_++;
    }

    uint16_t currentReadEpoch() const
    {
        return readEpoch_;
    }

    uint16_t currentWriteEpoch() const
    {
        return writeEpoch_;
    }

    uint64_t nextWriteSequence()
    {
        return writeSeqNumber_++;
    }

    uint64_t nextReadSequence() const
    {
        return readSeqNumber_;
    }

    void readAccept()
    {
        readSeqNumber_++;
    }

private:
    uint64_t writeSeqNumber_;
    uint64_t readSeqNumber_;
    uint16_t writeEpoch_;
    uint16_t readEpoch_;
};