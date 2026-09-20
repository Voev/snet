#include <stdexcept>
#include <cstring>
#include <filesystem>
#include <snet/io/controller.hpp>
#include <snet/io/config.hpp>

namespace
{

constexpr const char* kCreateSymbol = "CreateDriver";

} // namespace

namespace snet::io
{

Controller::Controller()
{
    options_.add<io::Config>();
}

Controller::~Controller() noexcept
{
    drivers_.clear();
}

std::shared_ptr<Driver> Controller::load(const DriverConfig& drvConfig)
{
    const std::string& path = drvConfig.getPath();
    if (path.empty())
    {
        return nullptr;
    }

    auto createDriver = import_alias<DriverCreator>(path, ::kCreateSymbol);
    auto driver = createDriver(drvConfig);
    if (!driver)
    {
        return nullptr;
    }

    const std::string name = driver->getName() ? driver->getName() : "";
    if (name.empty() || drivers_.count(name))
    {
        return nullptr;
    }

    auto section = options_.add<Config>(name);
    auto status = driver->declareOptions(*section);
    if (status != Status::Success)
    {
        return nullptr;
    }

    LoadedDriver entry;
    entry.driver = std::move(driver);
    entry.creator = std::move(createDriver);

    auto [it, ok] = drivers_.emplace(name, std::move(entry));
    if (!ok)
    {
        return nullptr;
    }

    return it->second.driver;
}

void Controller::unload(const std::string& name)
{
    auto it = drivers_.find(name);
    if (it == drivers_.end())
        return;

    drivers_.erase(it);
    options_.remove(name);
}

std::shared_ptr<Driver> Controller::get(const std::string& name)
{
    auto driver = drivers_.find(name);
    if (driver == drivers_.end())
    {
        return nullptr;
    }
    return driver->second.driver;
}

Status Controller::configure(const std::string& configPath)
{
    try
    {
        casket::opt::ConfigOptionsReader reader;
        std::ifstream ifs(configPath);
        if (!ifs)
            return Status::Error;

        reader.read(ifs, options_);
    }
    catch (const std::exception&)
    {
        return Status::Error;
    }

    return apply();
}

Status Controller::configure(const std::string& configPath, const std::string& name)
{
    auto it = drivers_.find(name);
    if (it == drivers_.end())
    {
        return Status::Error;
    }

    try
    {
        casket::opt::ConfigOptionsReader reader;
        std::ifstream ifs(configPath);
        if (!ifs)
            return Status::Error;

        reader.read(ifs, options_);
    }
    catch (const std::exception&)
    {
        return Status::Error;
    }

    auto* section = sectionFor(name);
    if (!section)
        return Status::Error;

    return it->second.driver->configure(*section);
}

Status Controller::apply()
{
    for (auto& [name, l] : drivers_)
    {
        auto* section = sectionFor(name);
        if (!section)
            return Status::Error;

        if (auto st = l.driver->configure(*section); st != Status::Success)
            return st;
    }
    return Status::Success;
}

} // namespace snet::io
