#pragma once
#include <memory>

template <typename T, void (*f)(T*)> struct static_function_deleter
{
    void operator()(T* t) const
    {
        f(t);
    }
};

#define DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(alias, object, deleter)          \
    struct alias : public std::unique_ptr<object, deleter>                     \
    {                                                                          \
        using unique_ptr::unique_ptr;                                          \
                                                                               \
        operator object*() const                                               \
        {                                                                      \
            return this->get();                                                \
        }                                                                      \
    }

#define DEFINE_CUSTOM_UNIQUE_PTR(alias, object, deleter)                       \
    using alias##Deleter = static_function_deleter<object, &deleter>;          \
    DEFINE_CUSTOM_UNIQUE_PTR_WITH_DELETER(alias, object, alias##Deleter)
