#include <dlfcn.h>
#include <stdexcept>
#include <snet/io/dynamic_library.hpp>
#include <casket/utils/exception.hpp>

namespace snet::io
{

DynamicLibrary::DynamicLibrary(std::string_view path)
    : handle_(::dlopen(path.data(), RTLD_LAZY))
{
    casket::ThrowIfFalse(handle_, "{}", ::dlerror());
}

DynamicLibrary::~DynamicLibrary() noexcept
{
    unload();
}

bool DynamicLibrary::isLoaded() const noexcept
{
    return (handle_ != nullptr);
}

void DynamicLibrary::unload() noexcept {
    if (isLoaded()) {
        ::dlclose(handle_);
        handle_ = nullptr;
    }
}

void* DynamicLibrary::resolveSymbol(std::string_view symbol) const
{
    casket::ThrowIfFalse(isLoaded(), "library is not loaded");

    void* addr = ::dlsym(handle_, symbol.data());
    casket::ThrowIfFalse(addr, "{}", ::dlerror());
    return addr;
}

} // namespace snet::io
