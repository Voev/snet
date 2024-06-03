#pragma once
#include <vector>
#include <string>
#include <string_view>
#include <snet/utils/noncopyable.hpp>

namespace snet
{

class Command : public utils::NonCopyable
{
public:
    Command() = default;

    virtual ~Command() = default;

    virtual std::string_view description() const = 0;

    virtual void execute(const std::vector<std::string>& args) = 0;
};

} // namespace snet