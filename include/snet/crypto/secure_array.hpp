#pragma once
#include <cstddef>
#include <algorithm>
#include <stdexcept>
#include <openssl/crypto.h>
#include <casket/nonstd/span.hpp>

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

    SecureArray()
        : size_(0)
    {
    }

    explicit SecureArray(size_type size)
        : size_(size)
    {
        if (size > N)
        {
            throw std::out_of_range("Requested size exceeds maximum capacity");
        }
    }

    ~SecureArray() noexcept
    {
        clear_memory();
    }

    SecureArray(const SecureArray&) = delete;
    SecureArray& operator=(const SecureArray&) = delete;

    SecureArray(SecureArray&& other) noexcept
        : size_(other.size_)
    {
        std::copy_n(other.data_, size_, data_);
        other.size_ = 0;
        OPENSSL_cleanse(other.data_, N);
    }

    operator nonstd::span<T>() noexcept
    {
        return nonstd::span<T>(data_, size_);
    }

    operator nonstd::span<const T>() const noexcept
    {
        return nonstd::span<const T>(data_, size_);
    }

    SecureArray& operator=(SecureArray&& other) noexcept
    {
        if (this != &other)
        {
            clear_memory();
            size_ = other.size_;
            std::copy_n(other.data_, size_, data_);
            other.size_ = 0;
            OPENSSL_cleanse(other.data_, N);
        }
        return *this;
    }

    template <typename InputIt>
    void assign(InputIt first, InputIt last)
    {
        size_type count = 0;
        T* dest = data_;

        while (first != last && count < N)
        {
            *dest++ = *first++;
            ++count;
        }

        if (first != last)
        {
            OPENSSL_cleanse(data_, count * sizeof(T));
            throw std::out_of_range("Requested size exceeds maximum capacity");
        }

        if (count < size_)
        {
            OPENSSL_cleanse(data_ + count, (size_ - count) * sizeof(T));
        }

        size_ = count;
    }

    void assign(nonstd::span<const T> value)
    {
        assign(value.begin(), value.end());
    }

    void resize(size_type newSize)
    {
        if (newSize > N)
        {
            throw std::out_of_range("Requested size exceeds maximum capacity");
        }

        if (newSize < size_)
        {
            OPENSSL_cleanse(data_ + newSize, size_ - newSize);
        }
        else if (newSize > size_)
        {
            std::fill_n(data_ + size_, newSize - size_, T{});
        }

        size_ = newSize;
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
        if (pos >= size_)
        {
            throw std::out_of_range("Index out of range");
        }
        return data_[pos];
    }

    const_reference at(size_type pos) const
    {
        if (pos >= size_)
        {
            throw std::out_of_range("Index out of range");
        }
        return data_[pos];
    }

    reference front()
    {
        if (size_ == 0)
            throw std::out_of_range("Array is empty");
        return data_[0];
    }

    const_reference front() const
    {
        if (size_ == 0)
            throw std::out_of_range("Array is empty");
        return data_[0];
    }

    reference back()
    {
        if (size_ == 0)
            throw std::out_of_range("Array is empty");
        return data_[size_ - 1];
    }

    const_reference back() const
    {
        if (size_ == 0)
            throw std::out_of_range("Array is empty");
        return data_[size_ - 1];
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
        return data_ + size_;
    }

    const_iterator end() const noexcept
    {
        return data_ + size_;
    }

    const_iterator cend() const noexcept
    {
        return data_ + size_;
    }

    size_type size() const noexcept
    {
        return size_;
    }

    size_type capacity() const noexcept
    {
        return N;
    }

    bool empty() const noexcept
    {
        return size_ == 0;
    }

    void fill(const T& value)
    {
        std::fill_n(data_, size_, value);
    }

    void clear() noexcept
    {
        OPENSSL_cleanse(data_, size_);
        size_ = 0;
    }

private:
    void clear_memory() noexcept
    {
        OPENSSL_cleanse(data_, N);
        size_ = 0;
    }

    T data_[N];
    size_type size_;
};

} // namespace snet::crypto