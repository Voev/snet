#pragma once
#include <string_view>
#include <system_error>

namespace snet::utils
{

class SystemError final : public std::system_error
{
public:
    SystemError(std::error_code ec)
        : std::system_error(ec)
    {
    }
    SystemError(std::error_code ec, std::string_view what)
        : std::system_error(ec, what.data())
    {
    }
};

class RuntimeError final : public std::runtime_error
{
public:
    RuntimeError(std::string_view what)
        : std::runtime_error(what.data())
    {
    }
};

inline void ThrowIfError(std::error_code ec)
{
    if (ec)
    {
        throw SystemError(ec);
    }
}

inline void ThrowIfError(std::error_code ec, std::string_view msg)
{
    if (ec)
    {
        throw SystemError(ec, msg);
    }
}

inline void ThrowIfTrue(bool exprResult, std::string_view msg)
{
    if (exprResult)
    {
        throw RuntimeError(msg.data());
    }
}

inline void ThrowIfFalse(bool exprResult, std::string_view msg)
{
    return ThrowIfTrue(!exprResult, msg);
}

} // namespace snet::utils