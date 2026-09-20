#pragma once
#include <string>
#include <snet/io/types.hpp>

namespace snet::io
{

class DriverConfig final
{
public:
    DriverConfig() = default;

    ~DriverConfig() noexcept = default;

    void setPath(std::string path)
    {
        path_ = std::move(path);
    }

    const std::string& getPath() const
    {
        return path_;
    }

private:
    std::string path_;
};

} // namespace snet::io