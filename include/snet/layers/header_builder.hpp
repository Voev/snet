#pragma once
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <endian.h>

namespace snet::layers
{

template <typename T>
struct is_span_like
{
private:
    template <typename U>
    static auto test(int) -> decltype(std::declval<U>().data(), std::declval<U>().size(), std::true_type{});

    template <typename>
    static std::false_type test(...);

public:
    static constexpr bool value = decltype(test<T>(0))::value;
};

template <typename T>
static constexpr bool is_span_like_v = is_span_like<T>::value;

template <typename HeaderType>
class HeaderBuilder
{
public:
    using AdvanceCallback = std::function<void(size_t bytes)>;

    explicit HeaderBuilder(uint8_t* buffer, size_t capacity, AdvanceCallback callback) noexcept
        : callback_(std::move(callback))
        , buffer_(buffer)
        , capacity_(capacity)
        , header_(nullptr)
        , built_(false)
    {
        if (buffer && capacity >= sizeof(HeaderType))
        {
            header_ = reinterpret_cast<HeaderType*>(buffer);
            std::memset(header_, 0, sizeof(HeaderType));
        }
    }

    template <typename FieldType, typename ValueType>
    HeaderBuilder& set(FieldType HeaderType::* field, ValueType&& value) noexcept
    {
        if (header_ && !built_)
        {
            setField(field, std::forward<ValueType>(value));
        }
        return *this;
    }

    size_t build() noexcept
    {
        built_ = true;
        size_t size = getHeaderSize();
        if (callback_) callback_(size);
        return size;
    }

    HeaderType* raw() noexcept
    {
        return header_;
    }
    const HeaderType* raw() const noexcept
    {
        return header_;
    }
    bool isBuilt() const noexcept
    {
        return built_;
    }
    bool isValid() const noexcept
    {
        return header_ != nullptr;
    }

private:
    template <typename FieldType, typename ValueType>
    void setField(FieldType HeaderType::* field, ValueType&& value) noexcept
    {
        header_->*field = std::forward<ValueType>(value);
    }

    template <typename T, size_t N, typename ValueType>
    void setField(T (HeaderType::*field)[N], ValueType&& value) noexcept
    {
        using DecayedType = std::decay_t<ValueType>;

        if constexpr (is_span_like_v<DecayedType>)
        {
            size_t copy_len = std::min(value.size(), N);
            std::memcpy(&(header_->*field), value.data(), copy_len * sizeof(T));
        }
        else if constexpr (std::is_pointer_v<DecayedType>)
        {
            std::memcpy(&(header_->*field), value, N * sizeof(T));
        }
        else if constexpr (std::is_array_v<DecayedType>)
        {
            std::memcpy(&(header_->*field), value, N * sizeof(T));
        }
        else
        {
            static_assert(std::is_trivially_copyable_v<ValueType>, "Array assignment requires trivially copyable type");
            std::memcpy(&(header_->*field), &value, N * sizeof(T));
        }
    }

    size_t getHeaderSize() const noexcept
    {
        if (!header_)
            return sizeof(HeaderType);

        if constexpr (std::is_same_v<HeaderType, ethernet_header>)
        {
            if (be16toh(header_->etherType) == 0x8100)
                return sizeof(ethernet_header) + 4;
            return sizeof(ethernet_header);
        }

        if constexpr (std::is_same_v<HeaderType, ipv4_header>)
        {
            return static_cast<size_t>(header_->ihl) * 4;
        }

        if constexpr (std::is_same_v<HeaderType, tcp_header>)
        {
            return static_cast<size_t>(header_->doff) * 4;
        }

        return sizeof(HeaderType);
    }

private:
    AdvanceCallback callback_;
    uint8_t* buffer_;
    size_t capacity_;
    HeaderType* header_;
    bool built_;
};

} // namespace snet::layers