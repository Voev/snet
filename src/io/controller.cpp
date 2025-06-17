#include <stdexcept>
#include <cstring>
#include <filesystem>
#include <snet/io/controller.hpp>
#include <snet/io/config.hpp>

namespace snet::io
{

Controller::Controller()
{
}

Controller::~Controller() noexcept
{
}

std::shared_ptr<Driver> Controller::load(const DriverConfig& drvConfig)
{
    std::function<DriverCreator> createDriver = import_alias<DriverCreator>(drvConfig.getPath(), "CreateDriver");

    auto driver = createDriver(drvConfig);

    drivers_[driver->getName()] = driver;

    return driver;
}

void Controller::unload(std::shared_ptr<Driver> driver)
{
    auto found = drivers_.find(driver->getName());
    if (found != drivers_.end())
    {
        drivers_.erase(found);
    }
}

std::shared_ptr<Driver> Controller::get(const std::string& name)
{
    auto driver = drivers_.find(name);
    if (driver == drivers_.end())
    {
        return nullptr;
    }
    return driver->second;
}

} // namespace snet::io
