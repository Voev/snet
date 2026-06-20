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

    virtual std::string getName() const = 0;

    virtual std::string getDescription() const = 0;

    virtual std::string getUsage() const = 0;

    virtual bool validateArgs(const std::vector<std::string>& args) const
    {
        (void)args;
        return true;
    }
};

} // namespace snet::cmd
