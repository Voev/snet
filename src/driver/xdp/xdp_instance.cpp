#include "xdp_instance.hpp"
#include "xdp_driver.hpp"

#include <net/if.h>
#include <unistd.h>

#include <casket/log/log.hpp>

namespace snet::driver
{

XdpInstance::XdpInstance(XdpDriver& driver)
    : driver_(driver)
{
}

XdpInstance::~XdpInstance() noexcept
{
    destroy();
}

bool XdpInstance::create(const std::string& iface, uint32_t queueId)
{
    name_ = iface;
    queueId_ = queueId;

    ifindex_ = ::if_nametoindex(iface.c_str());
    if (ifindex_ == 0)
    {
        driver_.logError("if_nametoindex(%s): %s", iface.c_str(), std::strerror(errno));
        return false;
    }
    return true;
}

bool XdpInstance::bindTo(struct xsk_umem* umem, const struct xsk_socket_config& cfg)
{
    if (::xsk_socket__create_shared(&xsk_, name_.c_str(), queueId_, umem, &rx_, &tx_, &fq_, &cq_, &cfg))
    {
        driver_.logError("xsk_socket__create_shared(%s, q=%u): %s", name_.c_str(), queueId_, std::strerror(errno));
        return false;
    }
    fd_ = ::xsk_socket__fd(xsk_);
    return true;
}

void XdpInstance::destroy() noexcept
{
    if (xsk_)
    {
        ::xsk_socket__delete(xsk_);
        xsk_ = nullptr;
        fd_ = -1;
    }
    active_ = false;
}

} // namespace snet::driver