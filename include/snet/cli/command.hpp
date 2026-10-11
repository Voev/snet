#pragma once
#include <vector>
#include <casket/nonstd/string_view.hpp>
#include <casket/utils/noncopyable.hpp>

namespace snet::cmd
{

class Command : public casket::NonCopyable
{
public:
    Command() = default;

    virtual ~Command() = default;

    virtual void execute(const std::vector<nonstd::string_view>& args) = 0;
};

} // namespace snet::cmd
