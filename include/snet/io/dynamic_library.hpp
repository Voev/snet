#pragma once
#include <string>
#include <memory>
#include <filesystem>
#include <type_traits>
#include <snet/utils/casting.hpp>

namespace snet::io
{

class DynamicLibrary final
{
public:
    explicit DynamicLibrary(std::string_view path);

    ~DynamicLibrary() noexcept;

    DynamicLibrary(const DynamicLibrary& other) = delete;
    DynamicLibrary& operator=(const DynamicLibrary& other) = delete;

    DynamicLibrary(DynamicLibrary&& other) noexcept = delete;
    DynamicLibrary& operator=(DynamicLibrary&& other) noexcept = delete;

    bool isLoaded() const noexcept;

    void unload() noexcept;

    void* resolveSymbol(std::string_view symbol) const;

    //! \overload T& get(const std::string& symbol_name) const
    template <typename T>
    inline typename std::enable_if<std::is_member_pointer<T>::value || std::is_reference<T>::value,
                                   T>::type
    get(std::string_view symbol_name) const
    {
        return utils::aggressive_ptr_cast<T>(resolveSymbol(symbol_name));
    }

    //! \overload T& get(const std::string& symbol_name) const
    template <typename T>
    inline
        typename std::enable_if<!(std::is_member_pointer<T>::value || std::is_reference<T>::value),
                                T&>::type
        get(std::string_view symbol_name) const
    {
        return *utils::aggressive_ptr_cast<T*>(resolveSymbol(symbol_name));
    }

private:
    void* handle_;
};

namespace detail
{

template <class T>
class library_function
{
    std::shared_ptr<T> f_;

public:
    inline library_function(const std::shared_ptr<DynamicLibrary>& lib, T* func_ptr) noexcept
        : f_(lib, func_ptr)
    {
    }

    // Compilation error at this point means that imported function
    // was called with unmatching parameters.
    //
    // Example:
    // auto f = dll::import_symbol<void(int)>("function", "lib.so");
    // f("Hello");  // error: invalid conversion from 'const char*' to 'int'
    // f(1, 2);     // error: too many arguments to function
    // f();         // error: too few arguments to function
    template <class... Args>
    inline auto operator()(Args&&... args) const -> decltype((*f_)(static_cast<Args&&>(args)...))
    {
        return (*f_)(static_cast<Args&&>(args)...);
    }
};

template <class T>
using import_type = typename std::conditional<std::is_object<T>::value, std::shared_ptr<T>,
                                              library_function<T> >::type;

} // namespace detail


template <class T>
inline detail::import_type<T> import_alias(const std::string& path, std::string_view name)
{
    using type = detail::import_type<T>;

    auto lib = std::make_shared<DynamicLibrary>(path);
    auto* addr = lib->get<T*>(name);
    return type(std::move(lib), addr);
}

} // namespace snet::io
