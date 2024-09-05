#pragma once
#include <chrono>
#include <functional>
#include <utility>

namespace snet::event
{

using Handler = std::function<void()>;
using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;

class Task
{
public:
    Task(Handler handler, const TimePoint& timePoint)
        : handler_(std::move(handler))
        , timePoint_(timePoint)
    {
    }

    const TimePoint& timePoint() const
    {
        return timePoint_;
    }

    bool operator>(const Task& other) const
    {
        return timePoint_ > other.timePoint_;
    }
    void operator()()
    {
        handler_();
    }

private:
    Handler handler_;
    TimePoint timePoint_;
};

} // namespace snet::event
