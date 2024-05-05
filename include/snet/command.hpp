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

    virtual void configure(const std::vector<std::string>& args) = 0;

    void run()
    {
        if(executable_)
        {
            execute();
        }
    }

protected:
    virtual void execute() = 0;

private:
    bool executable_{false};
};

} // namespace snet