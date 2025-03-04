#pragma once
#include <snet/daq/daq.h>
#include <string>
#include <unordered_map>

namespace snet::io
{

class Config;

class DriverConfig
{
public:
    using Parameters = std::unordered_map<std::string, std::string>;

    explicit DriverConfig(const Config& config, std::string name)
        : config_(config)
        , name_(std::move(name))
        , mode(DAQ_MODE_NONE)
    {
    }

    const Config& getConfig() const
    {
        return config_;
    }

    void setPath(std::string path)
    {
        path_ = std::move(path);
    }

    const std::string& getPath() const
    {
        return path_;
    }

    const std::string& getName() const
    {
        return name_;
    }

    int setMode(DAQ_Mode newMode)
    {
        mode = newMode;
        return DAQ_SUCCESS;
    }

    DAQ_Mode getMode() const
    {
        return mode;
    }

    int setVariable(const std::string& key, const std::string& value)
    {
        if (key.empty())
            return DAQ_ERROR_INVAL;
        parameters_[key] = value;
        return DAQ_SUCCESS;
    }

    const std::string getVariable(const std::string& key) const
    {
        auto it = parameters_.find(key);
        return it != parameters_.end() ? it->second : std::string();
    }

    const Parameters& getParameters() const
    {
        return parameters_;
    }

    int deleteVariable(const std::string& key)
    {
        if (key.empty())
            return DAQ_ERROR_INVAL;
        return parameters_.erase(key) ? DAQ_SUCCESS : DAQ_ERROR;
    }

private:
    const Config& config_;
    Parameters parameters_;
    std::string name_;
    std::string path_;
    DAQ_Mode mode;
};

} // namespace snet::io