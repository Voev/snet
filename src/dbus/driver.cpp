#include <stdexcept>
#include <snet/dbus/driver.hpp>
#include <snet/io/daq.h>

namespace snet::dbus
{

Driver::Driver(std::string_view path)
    : path_(path)
{
    if (path_.empty())
    {
        throw std::runtime_error("no module path specified ");
    }

    reload();
}

Driver::~Driver() noexcept
{
    if (api_)
    {
        api_->unload();
    }
}

void Driver::reload()
{
    if (api_)
    {
        api_->unload();
    }

    lib_ = std::make_unique<DynamicLibrary>(path_);
    api_ = lib_->resolve<DriverAPI_t*>("DAQ_MODULE_DATA");

    BaseAPI_t base;
    populate_base_api(&base);

    api_->load(&base);
}

} // namespace snet::dbus
