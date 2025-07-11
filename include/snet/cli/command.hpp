#pragma once
#include <vector>
#include <string_view>
#include <casket/utils/noncopyable.hpp>

namespace snet::cmd
{

class Command : public casket::NonCopyable
{
public:
    Command() = default;

    virtual ~Command() = default;

    virtual void execute(const std::vector<std::string_view>& args) = 0;
};

} // namespace snet::cmd
