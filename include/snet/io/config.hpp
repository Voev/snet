#pragma once
#include <string>
#include <snet/io/types.hpp>

namespace snet::io
{

class Config
{
public:
    Config()
        : input_()
        , msgPoolSize_(0U)
        , snaplen_(0U)
        , timeout_(0U)
        , mode_(Mode::None)
    {
    }

    ~Config() noexcept
    {
    }

    void setInput(std::string input)
    {
        input_ = std::move(input);
    }

    const std::string& getInput() const
    {
        return input_;
    }

    void setMsgPoolSize(uint32_t poolSize)
    {
        msgPoolSize_ = poolSize;
    }

    std::size_t getMsgPoolSize() const
    {
        return msgPoolSize_;
    }

    void setSnaplen(std::size_t snaplen)
    {
        snaplen_ = snaplen;
    }

    std::size_t getSnaplen() const
    {
        return snaplen_;
    }

    void setTimeout(unsigned new_timeout)
    {
        timeout_ = new_timeout;
    }

    unsigned getTimeout() const
    {
        return timeout_;
    }

    void setMode(Mode newMode)
    {
        mode_ = newMode;
    }

    Mode getMode() const
    {
        return mode_;
    }

private:
    std::string input_;
    std::size_t msgPoolSize_;
    std::size_t snaplen_;
    unsigned timeout_;
    Mode mode_;
};

} // namespace snet::io