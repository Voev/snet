#pragma once
#include <string>
#include <unordered_map>
#include <snet/io/types.hpp>

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
        , mode(Mode::None)
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

    void setMode(Mode newMode)
    {
        mode = newMode;
    }

    Mode getMode() const
    {
        return mode;
    }

    void setVariable(const std::string& key, const std::string& value)
    {
        parameters_[key] = value;
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

    void deleteVariable(const std::string& key)
    {
        parameters_.erase(key);
    }

private:
    const Config& config_;
    Parameters parameters_;
    std::string name_;
    std::string path_;
    Mode mode;
};

} // namespace snet::io