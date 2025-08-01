#pragma once
#include <cstdint>

namespace snet::tls
{

/// @brief TLS record layer sequence number tracker
class SequenceNumbers final
{
public:
    /// @brief Construct with both sequences initialized to 0
    SequenceNumbers() noexcept
        : clientSeqNumber_(0)
        , serverSeqNumber_(0)
    {
    }

    /// @brief Reset client sequence to 0
    void resetClientSequence() noexcept
    {
        clientSeqNumber_ = 0;
    }

    /// @brief Reset server sequence to 0
    void resetServerSequence() noexcept
    {
        serverSeqNumber_ = 0;
    }

    /// @brief Client sequence accessor
    /// @return Current client sequence number
    uint64_t getClientSequence() const noexcept
    {
        return clientSeqNumber_;
    }

    /// @brief Server sequence accessor
    /// @return Current server sequence number
    uint64_t getServerSequence() const noexcept
    {
        return serverSeqNumber_;
    }

    /// @brief Increment client sequence number
    void acceptClientSequence() noexcept
    {
        ++clientSeqNumber_;
    }
    
    /// @brief Increment server sequence number
    void acceptServerSequence() noexcept
    {
        ++serverSeqNumber_;
    }

private:
    uint64_t clientSeqNumber_; ///< Client sequence counter
    uint64_t serverSeqNumber_; ///< Server sequence counter
};

} // namespace snet::tls