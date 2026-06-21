#pragma once
#include <chrono>
#include <string>
#include <sstream>
#include <iomanip>
#include <casket/nonstd/optional.hpp>

namespace snet
{

using SystemClock = std::chrono::system_clock;
using SteadyClock = std::chrono::steady_clock;
using HighResClock = std::chrono::high_resolution_clock;

using SystemTimePoint = SystemClock::time_point;
using SteadyTimePoint = SteadyClock::time_point;

using Seconds = std::chrono::seconds;
using Minutes = std::chrono::minutes;
using Hours = std::chrono::hours;
using Days = std::chrono::days;
using Milliseconds = std::chrono::milliseconds;
using Microseconds = std::chrono::microseconds;

inline std::string FormatTime(const SystemTimePoint& time, const std::string& format = "%Y-%m-%d %H:%M:%S")
{
    auto time_t = SystemClock::to_time_t(time);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time_t), format.c_str());
    return ss.str();
}

inline std::string ToIso8601(const SystemTimePoint& time)
{
    return FormatTime(time, "%Y-%m-%dT%H:%M:%SZ");
}

inline nonstd::optional<SystemTimePoint> FromIso8601(const std::string& iso_string)
{
    std::tm tm = {};
    std::stringstream ss(iso_string);
    ss >> std::get_time(&tm, "%Y-%m-%dT%H:%M:%SZ");

    if (ss.fail())
    {
        return std::nullopt;
    }

    time_t time = timegm(&tm);
    return SystemClock::from_time_t(time);
}

inline SteadyTimePoint SystemToSteady(SystemTimePoint systemTime)
{
    auto nowSystem = SystemClock::now();
    auto nowSteady = SteadyClock::now();
    auto duration = systemTime - nowSystem;
    return nowSteady + duration;
}

} // namespace snet