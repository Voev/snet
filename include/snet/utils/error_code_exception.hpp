#pragma once
#include <string_view>
#include <system_error>

namespace snet::utils
{

class ErrorCodeException final : public std::system_error
{
public:
    ErrorCodeException(std::error_code ec)
        : std::system_error(ec)
    {
    }
    ErrorCodeException(std::error_code ec, std::string_view what)
        : std::system_error(ec, what.data())
    {
    }
};

#define THROW_IF_ERROR(ec)                                                     \
    {                                                                          \
        if (ec)                                                                \
            throw snet::utils::ErrorCodeException(ec);                         \
    }

#define THROW_WHAT_IF_ERROR(ec, what)                                          \
    {                                                                          \
        if (ec)                                                                \
            throw snet::utils::ErrorCodeException(ec, what);                   \
    }

} // namespace snet::utils