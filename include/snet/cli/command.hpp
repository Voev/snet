#pragma once
#include <vector>
#include <string_view>
#include <snet/utils/noncopyable.hpp>

namespace snet::cmd
{

class Command : public utils::NonCopyable
{
public:
    Command() = default;

    virtual ~Command() = default;

    virtual void execute(const std::vector<std::string_view>& args) = 0;
};

} // namespace snet::cmd
