#include <stdexcept>
#include <snet/io/driver.hpp>

#include <snet/api/daq.h>

namespace snet::io
{

Driver::Driver(std::string_view file_path)
    : path_(file_path)
{
    if (file_path.empty())
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
    api_ = lib_->resolve<DAQ_ModuleAPI_t*>("DAQ_MODULE_DATA");

    DAQ_BaseAPI_t base;
    populate_base_api(&base);

    api_->load(&base);
}

} // namespace snet::io
