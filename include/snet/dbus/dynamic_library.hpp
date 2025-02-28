#pragma once
#include <string>

namespace snet::dbus
{

class DynamicLibrary final
{
public:
    explicit DynamicLibrary(std::string path);

    ~DynamicLibrary() noexcept;

    DynamicLibrary(const DynamicLibrary& other) = delete;
    DynamicLibrary& operator=(const DynamicLibrary& other) = delete;

    DynamicLibrary(DynamicLibrary&& other) noexcept = delete;
    DynamicLibrary& operator=(DynamicLibrary&& other) noexcept = delete;

    void* resolveSymbol(const std::string& symbol);

    template <typename T>
    T resolve(const std::string& symbol)
    {
        return reinterpret_cast<T>(resolveSymbol(symbol));
    }

private:
    std::string path_;
    void* handle_;
};

} // namespace snet::dbus
