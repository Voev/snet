#pragma once
#include <memory>
#include <functional>

namespace snet::event
{

class Context;
class Service;

using Handler = std::function<void (Service&, uint32_t)>;
class Service : public std::enable_shared_from_this<Service>
{
public:
    explicit Service(Context& ctx)
        : ctx_(ctx)
    {}

    virtual ~Service() noexcept {}

    virtual int fd() const = 0;

    inline Context& ctx()
    {
        return ctx_;
    }

    inline void setHandler(Handler&& handler)
    {
        handler_ = std::move(handler);
    }

    inline void callHandler(Service& service, uint32_t events)
    {
        if(handler_.has_value())
        {
            handler_.value()(service, events);
        }
    }

private:
    Context& ctx_;
    std::optional<Handler> handler_;
};

} // namespace snet::event
