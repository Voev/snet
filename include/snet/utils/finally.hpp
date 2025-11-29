#pragma once
#include <functional>

class Finally
{
public:
    explicit Finally(std::function<void()> cleanup)
        : cleanup_(std::move(cleanup))
    {
    }

    ~Finally()
    {
        if (cleanup_)
        {
            cleanup_();
        }
    }

    Finally(const Finally&) = delete;
    Finally& operator=(const Finally&) = delete;

    Finally(Finally&& other) noexcept
        : cleanup_(std::move(other.cleanup_))
    {
        other.cleanup_ = nullptr;
    }

    Finally& operator=(Finally&& other) noexcept
    {
        if (this != &other)
        {
            cleanup_ = std::move(other.cleanup_);
            other.cleanup_ = nullptr;
        }
        return *this;
    }

private:
    std::function<void()> cleanup_;
};
