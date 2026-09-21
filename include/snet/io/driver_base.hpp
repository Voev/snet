#pragma once

#include <snet/io/driver.hpp>
#include <casket/log/async_logger.hpp>

#include <utility>

namespace snet::io
{

class DriverBase : public snet::io::Driver
{
public:
    ~DriverBase() noexcept override = default;

protected:
    DriverBase() noexcept = default;

    explicit DriverBase(const snet::io::DriverConfig& cfg)
        : log_(cfg.getLogger())
    {
        logInfo("driver '%s' constructed", cfg.getPath().c_str());
    }

    template <typename... Args>
    void log(casket::LogLevel level, const char* fmt, Args&&... args) const
    {
        if (log_ == nullptr || level > log_->getLevel())
            return;
        log_->logf(level, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void logEmergency(const char* fmt, Args&&... args) const
    {
        log(casket::LogLevel::EMERGENCY, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void logAlert(const char* fmt, Args&&... args) const
    {
        log(casket::LogLevel::ALERT, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void logCritical(const char* fmt, Args&&... args) const
    {
        log(casket::LogLevel::CRITICAL, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void logError(const char* fmt, Args&&... args) const
    {
        log(casket::LogLevel::ERROR, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void logWarning(const char* fmt, Args&&... args) const
    {
        log(casket::LogLevel::WARNING, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void logNotice(const char* fmt, Args&&... args) const
    {
        log(casket::LogLevel::NOTICE, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void logInfo(const char* fmt, Args&&... args) const
    {
        log(casket::LogLevel::INFO, fmt, std::forward<Args>(args)...);
    }

    template <typename... Args>
    void logDebug(const char* fmt, Args&&... args) const
    {
        log(casket::LogLevel::DEBUG, fmt, std::forward<Args>(args)...);
    }

private:
    casket::AsyncLogger* log_ = nullptr;
};

} // namespace snet::io