#pragma once
#include <chrono>
#include <sys/time.h>
#include <ctime>
#include <string>
#include <sstream>
#include <iomanip>

namespace snet::layers
{

/// @brief Represents a packet timestamp.
class Timestamp
{
public:
    using seconds_type = std::time_t;
    using microseconds_type = suseconds_t;

    [[nodiscard]] static Timestamp currentTime() noexcept
    {
        timeval tv;
        gettimeofday(&tv, nullptr);
        return Timestamp{tv};
    }

    [[nodiscard]] static Timestamp clockRealtime() noexcept
    {
        timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        return Timestamp{ts};
    }

    [[nodiscard]] static Timestamp clockMonotonic() noexcept
    {
        timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        return Timestamp{ts};
    }

    constexpr Timestamp() noexcept = default;

    template <typename Rep, typename Period>
    explicit constexpr Timestamp(const std::chrono::duration<Rep, Period>& duration) noexcept
        : duration_{std::chrono::duration_cast<std::chrono::nanoseconds>(duration)}
    {
    }

    explicit constexpr Timestamp(const timeval& time_val) noexcept
        : duration_{std::chrono::seconds{time_val.tv_sec} + std::chrono::microseconds{time_val.tv_usec}}
    {
    }

    explicit constexpr Timestamp(const timespec& time_spec) noexcept
        : duration_{std::chrono::seconds{time_spec.tv_sec} + std::chrono::nanoseconds{time_spec.tv_nsec}}
    {
    }

    [[nodiscard]] constexpr seconds_type seconds() const noexcept
    {
        return std::chrono::duration_cast<std::chrono::seconds>(duration_).count();
    }

    [[nodiscard]] constexpr microseconds_type microseconds() const noexcept
    {
        auto micros = duration_ - std::chrono::seconds{seconds()};
        return std::chrono::duration_cast<std::chrono::microseconds>(micros).count();
    }

    [[nodiscard]] constexpr long nanoseconds() const noexcept
    {
        auto nanos = duration_ - std::chrono::seconds{seconds()};
        return nanos.count();
    }

    [[nodiscard]] constexpr auto totalMicroseconds() const noexcept
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(duration_).count();
    }

    [[nodiscard]] constexpr auto totalNanoseconds() const noexcept
    {
        return duration_.count();
    }

    explicit constexpr operator std::chrono::microseconds() const noexcept
    {
        return std::chrono::duration_cast<std::chrono::microseconds>(duration_);
    }

    explicit constexpr operator std::chrono::nanoseconds() const noexcept
    {
        return duration_;
    }

    [[nodiscard]] constexpr auto duration() const noexcept
    {
        return duration_;
    }

    [[nodiscard]] constexpr auto operator<=>(const Timestamp& other) const noexcept = default;

    /// @brief Template method for conversion to any clock time_point
    /// @tparam Clock The clock type to convert to (default: high_resolution_clock)
    /// @return Time point of the specified clock type
    template <typename Clock = std::chrono::high_resolution_clock>
    [[nodiscard]] typename Clock::time_point toTimePoint() const noexcept
    {
        return typename Clock::time_point{std::chrono::duration_cast<typename Clock::duration>(duration_)};
    }

    /// @brief Format options for toString()
    enum class Format
    {
        Default,       // YYYY-MM-DD HH:MM:SS.mmmuuu
        ISO8601,       // YYYY-MM-DDTHH:MM:SS.mmmuuuZ
        Unix,          // seconds.microseconds
        HumanReadable, // YYYY-MM-DD HH:MM:SS
        FullPrecision, // YYYY-MM-DD HH:MM:SS.mmmuuunnn
        LogFormat      // [YYYY-MM-DD HH:MM:SS.mmmuuu]
    };

    [[nodiscard]] std::string toString(Format format = Format::Default) const
    {
        const auto sec = seconds();
        const auto usec = microseconds();

        switch (format)
        {
        case Format::Unix:
            return unixFormat(sec, usec);
        case Format::HumanReadable:
            return humanReadableFormat(sec);
        case Format::ISO8601:
            return iso8601Format(sec, usec);
        case Format::FullPrecision:
            return fullPrecisionFormat(sec);
        case Format::LogFormat:
            return logFormat(sec, usec);
        default:
            return defaultFormat(sec, usec);
        }
    }

    [[nodiscard]] std::string toString(const std::string& format) const
    {
        return customFormat(format);
    }

private:
    std::string defaultFormat(seconds_type sec, microseconds_type usec) const;

    std::string iso8601Format(seconds_type sec, microseconds_type usec) const;

    std::string unixFormat(seconds_type sec, microseconds_type usec) const;

    std::string humanReadableFormat(seconds_type sec) const;

    std::string fullPrecisionFormat(seconds_type sec) const;

    std::string logFormat(seconds_type sec, microseconds_type usec) const;

    std::string customFormat(const std::string& format) const;

private:
    std::chrono::nanoseconds duration_{0};
};

} // namespace snet::layers