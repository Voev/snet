#pragma once
#include <string>
#include <unordered_map>
#include <snet/io/types.hpp>

namespace snet::io
{

class Config
{
public:
    using Parameters = std::unordered_map<std::string, std::string>;

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

    void setVariable(std::string key, std::string value)
    {
        parameters_[std::move(key)] = std::move(value);
    }

    std::string getVariable(const std::string& key) const
    {
        auto it = parameters_.find(key);
        return it != parameters_.end() ? it->second : std::string();
    }

    const Parameters& getParameters() const
    {
        return parameters_;
    }

    void deleteVariable(const std::string& key)
    {
        parameters_.erase(key);
    }

private:
    Parameters parameters_;
    std::string input_;
    std::size_t msgPoolSize_;
    std::size_t snaplen_;
    unsigned timeout_;
    Mode mode_;
};

} // namespace snet::io