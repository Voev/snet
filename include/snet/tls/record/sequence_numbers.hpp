#pragma once
#include <cstdint>

class SequenceNumbers final
{
public:
    SequenceNumbers() noexcept
    {
        resetClientSequence();
        resetServerSequence();
    }

    ~SequenceNumbers() noexcept
    {
    }

    inline void resetClientSequence() noexcept
    {
        clientSeqNumber_ = 0;
    }

    
    inline void resetServerSequence() noexcept
    {
        serverSeqNumber_ = 0;
    }

    inline uint64_t getClientSequence() const noexcept
    {
        return clientSeqNumber_;
    }

    inline uint64_t getServerSequence() const noexcept
    {
        return serverSeqNumber_;
    }

    inline void clientAccept() noexcept
    {
        clientSeqNumber_++;
    }

    inline void serverAccept() noexcept
    {
        serverSeqNumber_++;
    }

private:
    uint64_t clientSeqNumber_;
    uint64_t serverSeqNumber_;
};