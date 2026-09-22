#pragma once
#include <string>
#include <memory>
#include <functional>
#include <unordered_map>
#include <snet/io/driver.hpp>
#include <snet/io/driver_spec.hpp>
#include <snet/io/config.hpp>

namespace snet::io
{

class Controller final
{
public:
    using Options = casket::opt::ConfigOptions;

    explicit Controller(Options& options);
    ~Controller() noexcept;

    Controller(const Controller&) = delete;
    Controller& operator=(const Controller&) = delete;

    Controller(Controller&&) = delete;
    Controller& operator=(Controller&&) = delete;

    std::shared_ptr<Driver> load(const DriverSpec& config);

    void unload(const std::string& name);

    std::shared_ptr<Driver> get(const std::string& name);

    Options& options() noexcept
    {
        return options_;
    }

    const Options& options() const noexcept
    {
        return options_;
    }

    Config* sectionFor(const std::string& name) noexcept
    {
        return dynamic_cast<Config*>(options_.find(name));
    }

    const Config* sectionFor(const std::string& name) const noexcept
    {
        return dynamic_cast<const Config*>(options_.find(name));
    }

    Status configure(const std::string& name);

    Status configureAll();

private:
    struct LoadedDriver
    {
        std::function<DriverCreator> creator;
        std::shared_ptr<Driver> driver;
    };

    std::unordered_map<std::string, LoadedDriver> drivers_;
    Options& options_;
};

} // namespace snet::io
