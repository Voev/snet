#pragma once
#include <string>
#include <system_error>
#include <snet/utils/singleton.hpp>

namespace snet::tls
{

class ErrorCategory final : public utils::Singleton<ErrorCategory>,
                            public std::error_category
{
public:
    const char* name() const noexcept override;

    std::string message(int value) const override;
};

} // namespace snet::tls