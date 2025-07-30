#pragma once
#include <cstddef>
#include <algorithm>
#include <openssl/crypto.h>

namespace snet::crypto
{

template <typename T, size_t N>
class SecureArray final
{
public:
    using value_type = T;
    using size_type = size_t;
    using reference = T&;
    using const_reference = const T&;
    using pointer = T*;
    using const_pointer = const T*;
    using iterator = T*;
    using const_iterator = const T*;

    SecureArray() = default;

    ~SecureArray() noexcept
    {
        OPENSSL_cleanse(data_, N);
    }

    reference operator[](size_type pos)
    {
        return data_[pos];
    }

    const_reference operator[](size_type pos) const
    {
        return data_[pos];
    }

    reference at(size_type pos)
    {
        if (pos >= N)
        {
            throw std::out_of_range("Index out of range");
        }
        return data_[pos];
    }

    const_reference at(size_type pos) const
    {
        if (pos >= N)
        {
            throw std::out_of_range("Index out of range");
        }
        return data_[pos];
    }

    reference front()
    {
        return data_[0];
    }
    const_reference front() const
    {
        return data_[0];
    }

    reference back()
    {
        return data_[N - 1];
    }
    const_reference back() const
    {
        return data_[N - 1];
    }

    T* data() noexcept
    {
        return data_;
    }
    const T* data() const noexcept
    {
        return data_;
    }

    iterator begin() noexcept
    {
        return data_;
    }
    const_iterator begin() const noexcept
    {
        return data_;
    }
    const_iterator cbegin() const noexcept
    {
        return data_;
    }

    iterator end() noexcept
    {
        return data_ + N;
    }
    const_iterator end() const noexcept
    {
        return data_ + N;
    }
    const_iterator cend() const noexcept
    {
        return data_ + N;
    }

    constexpr size_type size() const noexcept
    {
        return N;
    }

    constexpr bool empty() const noexcept
    {
        return N == 0;
    }

    void fill(const T& value)
    {
        std::fill_n(data_, N, value);
    }

private:
    T data_[N];
};

} // namespace snet::crypto