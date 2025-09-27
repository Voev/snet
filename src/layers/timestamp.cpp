#include <snet/layers/timestamp.hpp>

namespace snet::layers
{

// Format implementations
std::string Timestamp::defaultFormat(seconds_type sec, microseconds_type usec) const
{
    std::tm tm;
    localtime_r(&sec, &tm);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0') << std::setw(6) << usec;
    return oss.str();
}

std::string Timestamp::iso8601Format(seconds_type sec, microseconds_type usec) const
{
    std::tm tm;
    gmtime_r(&sec, &tm);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(6) << usec << 'Z';
    return oss.str();
}

std::string Timestamp::unixFormat(seconds_type sec, microseconds_type usec) const
{
    return std::to_string(sec) + "." + std::to_string(usec);
}

std::string Timestamp::humanReadableFormat(seconds_type sec) const
{
    std::tm tm;
    localtime_r(&sec, &tm);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

std::string Timestamp::fullPrecisionFormat(seconds_type sec) const
{
    std::tm tm;
    localtime_r(&sec, &tm);

    auto nanos = (duration_ - std::chrono::seconds{sec}).count();
    
    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
        << '.' << std::setfill('0') << std::setw(9) << nanos;
    return oss.str();
}

std::string Timestamp::logFormat(seconds_type sec, microseconds_type usec) const
{
    std::tm tm;
    localtime_r(&sec, &tm);

    std::ostringstream oss;
    oss << '[' << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0') << std::setw(6) << usec << ']';
    return oss.str();
}

std::string Timestamp::customFormat(const std::string& format) const
{
    std::tm tm;
    auto secs = seconds();
    localtime_r(&secs, &tm);

    std::string result;
    result.reserve(format.size() + 20);

    for (size_t i = 0; i < format.size(); ++i)
    {
        if (format[i] == '%' && i + 1 < format.size())
        {
            if (format[i + 1] == 'f')
            {
                // Microseconds
                std::ostringstream micro_oss;
                micro_oss << std::setfill('0') << std::setw(6) << microseconds();
                result += micro_oss.str();
                ++i;
            }
            else if (format[i + 1] == 'n')
            {
                // Nanoseconds
                auto nanos =
                    duration_cast<std::chrono::nanoseconds>(duration_ - std::chrono::seconds{seconds()}).count();
                std::ostringstream nano_oss;
                nano_oss << std::setfill('0') << std::setw(9) << nanos;
                result += nano_oss.str();
                ++i;
            }
            else
            {
                // Standard strftime format
                char buffer[128];
                strftime(buffer, sizeof(buffer), std::string("%").append(1, format[i + 1]).c_str(), &tm);
                result += buffer;
                ++i;
            }
        }
        else
        {
            result += format[i];
        }
    }

    return result;
}

} // namespace snet::layers