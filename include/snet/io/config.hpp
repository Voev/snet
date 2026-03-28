#pragma once
#include <string>
#include <unordered_map>
#include <snet/io/types.hpp>

namespace snet::io
{

/// @brief Configuration container for driver settings.
class Config
{
public:
    using Parameters = std::unordered_map<std::string, std::string>; ///< Key-value parameter map.

    /// @brief Default constructor.
    Config()
        : input_()
        , msgPoolSize_(0U)
        , snaplen_(0U)
        , timeout_(0U)
        , mode_(Mode::None)
    {
    }

    /// @brief Destructor.
    ~Config() noexcept
    {
    }

    /// @brief Sets input source (device name or file path).
    /// @param[in] input Input source string.
    void setInput(std::string input)
    {
        input_ = std::move(input);
    }

    /// @brief Gets input source.
    /// @return Input source string.
    const std::string& getInput() const
    {
        return input_;
    }

    /// @brief Sets message pool size.
    /// @param[in] poolSize Number of packets in pool.
    void setMsgPoolSize(uint32_t poolSize)
    {
        msgPoolSize_ = poolSize;
    }

    /// @brief Gets message pool size.
    /// @return Pool size.
    std::size_t getMsgPoolSize() const
    {
        return msgPoolSize_;
    }

    /// @brief Sets snapshot length.
    /// @param[in] snaplen Maximum packet capture length.
    void setSnaplen(std::size_t snaplen)
    {
        snaplen_ = snaplen;
    }

    /// @brief Gets snapshot length.
    /// @return Snapshot length.
    std::size_t getSnaplen() const
    {
        return snaplen_;
    }

    /// @brief Sets read timeout.
    /// @param[in] new_timeout Timeout in milliseconds.
    void setTimeout(unsigned new_timeout)
    {
        timeout_ = new_timeout;
    }

    /// @brief Gets read timeout.
    /// @return Timeout in milliseconds.
    unsigned getTimeout() const
    {
        return timeout_;
    }

    /// @brief Sets operation mode.
    /// @param[in] newMode Mode (Live or Offline).
    void setMode(Mode newMode)
    {
        mode_ = newMode;
    }

    /// @brief Gets operation mode.
    /// @return Current mode.
    Mode getMode() const
    {
        return mode_;
    }

    /// @brief Sets custom configuration variable.
    /// @param[in] key Variable name.
    /// @param[in] value Variable value.
    void setVariable(std::string key, std::string value)
    {
        parameters_[std::move(key)] = std::move(value);
    }

    /// @brief Gets custom configuration variable.
    /// @param[in] key Variable name.
    /// @return Variable value or empty string if not found.
    std::string getVariable(const std::string& key) const
    {
        auto it = parameters_.find(key);
        return it != parameters_.end() ? it->second : std::string();
    }

    /// @brief Gets all custom parameters.
    /// @return Reference to parameters map.
    const Parameters& getParameters() const
    {
        return parameters_;
    }

    /// @brief Deletes custom configuration variable.
    /// @param[in] key Variable name to remove.
    void deleteVariable(const std::string& key)
    {
        parameters_.erase(key);
    }

private:
    Parameters parameters_;   ///< Custom key-value parameters.
    std::string input_;       ///< Input source (device or file).
    std::size_t msgPoolSize_; ///< Packet pool size.
    std::size_t snaplen_;     ///< Snapshot length.
    unsigned timeout_;        ///< Read timeout in milliseconds.
    Mode mode_;               ///< Operation mode.
};

} // namespace snet::io