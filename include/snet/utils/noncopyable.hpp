#pragma once

namespace snet::utils
{

class NonCopyable
{
public:
    NonCopyable() = default;
    virtual ~NonCopyable() = default;

    NonCopyable(const NonCopyable& other) = delete;
    NonCopyable& operator=(const NonCopyable& other) = delete;
};

} // namespace snet::utils