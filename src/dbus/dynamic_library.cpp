#include <dlfcn.h>
#include <stdexcept>
#include <snet/dbus/dynamic_library.hpp>
#include <casket/utils/exception.hpp>

namespace snet::dbus
{

DynamicLibrary::DynamicLibrary(std::string path)
    : path_(std::move(path))
    , handle_(nullptr)
{
    handle_ = ::dlopen(path_.c_str(), RTLD_LAZY);
    casket::utils::ThrowIfFalse(handle_, "{}", ::dlerror());
}

DynamicLibrary::~DynamicLibrary() noexcept
{
    ::dlclose(handle_);
}

void* DynamicLibrary::resolveSymbol(const std::string& symbol)
{
    void* addr = ::dlsym(handle_, symbol.c_str());
    casket::utils::ThrowIfFalse(addr, "{}: failed to resolve symbol '{}'", path_, symbol);
    return addr;
}

} // namespace snet::dbus
