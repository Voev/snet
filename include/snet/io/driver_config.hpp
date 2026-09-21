#pragma once
#include <string>
#include <snet/io/types.hpp>
#include <casket/log/log.hpp>

namespace snet::io
{

class DriverConfig final
{
public:
    using LoggerType = casket::AsyncLogger;

    DriverConfig() = default;

    ~DriverConfig() noexcept = default;

    void setPath(std::string path)
    {
        path_ = std::move(path);
    }

    const std::string& getPath() const
    {
        return path_;
    }

    void setLogger(LoggerType* logger)
    {
        logger_ = logger;
    }

    LoggerType* getLogger() const
    {
        return logger_;
    }

private:
    std::string path_;
    LoggerType* logger_{nullptr};
};

} // namespace snet::io