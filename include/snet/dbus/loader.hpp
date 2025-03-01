#pragma once
#include <algorithm>
#include <string>
#include <memory>
#include <unordered_set>
#include <snet/dbus/driver.hpp>

namespace snet::dbus
{

class Manager
{
public:
    static Manager& getInstance()
    {
        static Manager instance;
        return instance;
    }

    std::string loadModule(const std::string& path)
    {
        auto mod = std::make_shared<Driver>(path);
        libs_.insert(mod);
        return mod->getName().data();
    }

    void unloadModule(const std::string& name)
    {
        auto it =
            std::find_if(libs_.begin(), libs_.end(), [&name](const std::shared_ptr<Driver>& driver)
                         { return driver->getName() == name; });
        if (it != libs_.end())
        {
            libs_.erase(it);
        }
    }

    std::shared_ptr<Driver> getModule(const std::string& name)
    {
        auto it =
            std::find_if(libs_.begin(), libs_.end(), [&name](const std::shared_ptr<Driver>& driver)
                         { return driver->getName() == name; });

        if (it != libs_.end())
        {
            return *it;
        }
        return nullptr;
    }

    ~Manager()
    {
    }

    auto begin()
    {
        return libs_.begin();
    }

    auto end()
    {
        return libs_.end();
    }

private:
    Manager() = default;
    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

    struct Hash
    {
        std::size_t operator()(const std::shared_ptr<Driver>& module) const
        {
            return std::hash<std::string_view>()(module->getName());
        }
    };

    struct Equal
    {
        bool operator()(const std::shared_ptr<Driver>& lhs,
                        const std::shared_ptr<Driver>& rhs) const
        {
            return lhs->getName() == rhs->getName();
        }
    };

    std::unordered_set<std::shared_ptr<Driver>, Hash, Equal> libs_;
};

} // namespace snet::dbus
