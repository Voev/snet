#pragma once

namespace snet::utils
{

template <typename T> class Singleton
{
public:
    static T& Instance()
    {
        static T instance;
        return instance;
    }

    Singleton() = default;
    virtual ~Singleton() = default;

    Singleton(const Singleton& other) = delete;
    Singleton(Singleton&& other) = delete;

    Singleton& operator=(const Singleton& other) = delete;
    Singleton& operator=(Singleton&& other) = delete;
};

} // namespace snet::utils