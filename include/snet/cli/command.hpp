#pragma once
#include <vector>
#include <string>
#include <snet/utils/noncopyable.hpp>

namespace snet::cmd
{

class Command : public utils::NonCopyable
{
public:
    Command() = default;

    virtual ~Command() = default;

    virtual void execute(const std::vector<std::string>& args) = 0;
};

} // namespace snet::cmd
