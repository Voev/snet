#pragma once
#include <vector>
#include <string>
#include <casket/utils/result.hpp>

namespace snet::cmd
{

template <typename ResultType, typename ErrorType>
class Command
{
public:
    using Result = casket::Result<ResultType, ErrorType>;

    virtual ~Command() = default;

    Command(const Command& other) = delete;

    Command& operator=(const Command& other) = delete;

    virtual Result execute(const std::vector<std::string>& args) = 0;
};

} // namespace snet::cmd
