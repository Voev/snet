// snet/layers/header_builder.hpp
#pragma once
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <endian.h>

namespace snet::layers
{

// ====== SFINAE: проверка на span-подобность ======
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

/// @brief Универсальный строитель заголовков.
template <typename HeaderType>
class HeaderBuilder
{
public:
    explicit HeaderBuilder(uint8_t* buffer, size_t capacity) noexcept
        : buffer_(buffer)
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

    /// @brief Устанавливает поле с perfect forwarding.
    template <typename FieldType, typename ValueType>
    HeaderBuilder& set(FieldType HeaderType::* field, ValueType&& value) noexcept
    {
        if (header_ && !built_)
        {
            set_field(field, std::forward<ValueType>(value));
        }
        return *this;
    }

    /// @brief Строит заголовок и возвращает размер.
    size_t build() noexcept
    {
        built_ = true;
        return getHeaderSize();
    }

    // ====== ACCESSORS ======

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
    // ====== Обычные поля ======
    template <typename FieldType, typename ValueType>
    void set_field(FieldType HeaderType::* field, ValueType&& value) noexcept
    {
        header_->*field = std::forward<ValueType>(value);
    }

    // ====== Массивы ======
    template <typename T, size_t N, typename ValueType>
    void set_field(T (HeaderType::*field)[N], ValueType&& value) noexcept
    {
        using DecayedType = std::decay_t<ValueType>;

        // Проверяем, является ли value span-подобным
        if constexpr (is_span_like_v<DecayedType>)
        {
            // Для span/array/vector — копируем по размеру
            size_t copy_len = std::min(value.size(), N);
            std::memcpy(&(header_->*field), value.data(), copy_len * sizeof(T));
        }
        else if constexpr (std::is_pointer_v<DecayedType>)
        {
            // Для сырого указателя — просто копируем N элементов
            std::memcpy(&(header_->*field), value, N * sizeof(T));
        }
        else if constexpr (std::is_array_v<DecayedType>)
        {
            // Для массива — копируем
            std::memcpy(&(header_->*field), value, N * sizeof(T));
        }
        else
        {
            // Для присваивания скалярных значений (например, int[2] = {1,2})
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

    uint8_t* buffer_;
    size_t capacity_;
    HeaderType* header_;
    bool built_;
};

} // namespace snet::layers