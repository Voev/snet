#pragma once
#include <snet/network/ipv4_address.hpp>
#include <snet/network/ipv6_address.hpp>

namespace snet::network
{

class IPAddress final
{
public:
    /// @brief Конструктор по умолчанию.
    inline IPAddress() noexcept
        : type_(IPv4)
        , ipv4_()
        , ipv6_()
    {
    }

    /// @brief Конструктор создания IP-адреса из объекта IPv4.
    /// @param other Объекта класса IPv4.
    inline IPAddress(const IPv4Address& addr) noexcept
        : type_(IPv4)
        , ipv4_(addr)
        , ipv6_()
    {
    }

    /// @brief Конструктор создания IP-адреса из объекта IPv6.
    /// @param other Объекта класса IPv6.
    inline IPAddress(const IPv6Address& addr) noexcept
        : type_(IPv6)
        , ipv4_()
        , ipv6_(addr)
    {
    }

    /// @brief Деструктор по умолчанию.
    ~IPAddress() = default;

    /// @brief Конструктор копирования из объекта класса IP-адреса.
    /// @param other const-ссылка на объект класса.
    inline IPAddress(const IPAddress& other) noexcept
        : type_(other.type_)
        , ipv4_(other.ipv4_)
        , ipv6_(other.ipv6_)
    {
    }

    /// @brief Конструктор перемещения из объекта класса IP-адреса.
    /// @param other rvalue-ссылка на объект класса.
    inline IPAddress(IPAddress&& other) noexcept
        : type_(other.type_)
        , ipv4_(other.ipv4_)
        , ipv6_(other.ipv6_)
    {
    }

    /// @brief Оператор присвоения из объекта класса IP-адреса.
    /// @param other const-ссылка на объект класса.
    /// @return Ссылка на объект класса IP-адреса.
    inline IPAddress& operator=(const IPAddress& other) noexcept
    {
        type_ = other.type_;
        ipv4_ = other.ipv4_;
        ipv6_ = other.ipv6_;
        return *this;
    }

    /// @brief Оператор перемещения из объекта класса IP-адреса.
    /// @param other rvalue-ссылка на объект класса.
    /// @return Ссылка на объект класса IP-адреса.
    inline IPAddress& operator=(IPAddress&& other) noexcept
    {
        type_ = other.type_;
        ipv4_ = other.ipv4_;
        ipv6_ = other.ipv6_;
        return *this;
    }

    /// @brief Оператор присвоения из объекта класса IPv4-адреса.
    /// @param other const-ссылка на объект класса IPv4-адреса.
    /// @return Ссылка на объект класса IP-адреса.
    inline IPAddress& operator=(const IPv4Address& other) noexcept
    {
        type_ = IPv4;
        ipv4_ = other;
        ipv6_ = IPv6Address();
        return *this;
    }

    /// @brief Оператор присвоения из объекта класса IPv6-адреса.
    /// @param other const-ссылка на объект класса IPv6-адреса.
    /// @return Ссылка на объект класса IP-адреса.
    inline IPAddress& operator=(const IPv6Address& other) noexcept
    {
        type_ = IPv6;
        ipv4_ = IPv4Address();
        ipv6_ = other;
        return *this;
    }

    /// @brief Метод преобразования IP-адреса в строку.
    ///
    /// @param ec Код ошибки, если произошла ошибка.
    ///
    /// @return Строковое представление IP-адреса.
    inline std::optional<std::string>
    toString(std::error_code& ec) const noexcept
    {
        if (type_ == IPv6)
        {
            return ipv6_.toString(ec);
        }
        return ipv4_.toString(ec);
    }

    /// @brief Метод преобразования IP-адреса в строку.
    ///
    /// @throws std::system_error.
    ///
    /// @return Строковое представление IP-адреса.
    inline std::optional<std::string> toString() const
    {
        if (type_ == IPv6)
        {
            return ipv6_.toString();
        }
        return ipv4_.toString();
    }

    /// @brief Функция создания IP-адреса из строки c проверкой состояния
    /// ошибки.
    ///
    /// @param str Строка, содержащая IP-адрес.
    /// @param ec Код ошибки, если произошла ошибка.
    ///
    /// @return Объект класса IP-адреса.
    inline static std::optional<IPAddress>
    fromString(const char* str, std::error_code& ec) noexcept
    {
        auto ipv6 = IPv6Address::fromString(str, ec);
        if (!ec && ipv6.has_value())
            return IPAddress(ipv6.value());

        ec.clear();
        auto ipv4 = IPv4Address::fromString(str, ec);
        if (!ec && ipv4.has_value())
            return IPAddress(ipv4.value());

        return std::nullopt;
    }

    inline static std::optional<IPAddress>
    fromBytes(const std::uint8_t* bytes, std::size_t length,
              std::error_code& ec) noexcept
    {
        auto ipv6 = IPv6Address::fromBytes(bytes, length, ec);
        if (!ec && ipv6.has_value())
            return IPAddress(ipv6.value());

        ec.clear();
        auto ipv4 = IPv4Address::fromBytes(bytes, length, ec);
        if (!ec && ipv4.has_value())
            return IPAddress(ipv4.value());

        return std::nullopt;
    }

    /// @brief Функция создания IP-адреса из строки.
    ///
    /// @param str Строка, содержащая IP-адрес.
    /// @throws std::system_error.
    ///
    /// @return Объект класса IP-адреса.
    inline static std::optional<IPAddress> fromString(const char* str)
    {
        std::error_code ec;
        auto ret = fromString(str, ec);
        if (ec)
            throw ec;
        return ret;
    }

    /// @brief Метод проверки соответствия типа IPv4.
    ///
    /// @retval true Тип соответствует версии IPv4.
    /// @retval false Тип не соответствует версии IPv4.
    inline bool isIPv4() const noexcept
    {
        return type_ == IPv4;
    }

    /// @brief Метод проверки соответствия типа IPv6.
    ///
    /// @retval true Тип соответствует версии IPv6.
    /// @retval false Тип не соответствует версии IPv6.
    inline bool isIPv6() const noexcept
    {
        return type_ == IPv6;
    }

    /// @brief Метод преобразования в структуру адреса IPv4, если класс имеет
    /// соответствующий тип.
    ///
    /// @throws std::bad_cast.
    /// @return Скопированный объект класса адреса IPv4.
    inline IPv4Address toIPv4() const
    {
        if (type_ != IPv4)
        {
            throw std::bad_cast();
        }
        return ipv4_;
    }

    /// @brief Метод преобразования в структуру адреса IPv6, если класс имеет
    /// соответствующий тип.
    ///
    /// @throws std::bad_cast.
    /// @return Скопированный объект класса адреса IPv6.
    inline IPv6Address toIPv6() const
    {
        if (type_ != IPv6)
        {
            throw std::bad_cast();
        }
        return ipv6_;
    }

    /// @brief Оператор проверки на равенство.
    /// @param a Первый аргумент операции сравнения.
    /// @param b Второй аргумент операции сравнения.
    /// @retval true если a == b.
    /// @retval false если a != b.
    inline friend bool operator==(const IPAddress& a,
                                  const IPAddress& b) noexcept
    {
        if (a.type_ != b.type_)
            return false;
        if (a.type_ == IPv6)
            return a.ipv6_ == b.ipv6_;
        return a.ipv4_ == a.ipv4_;
    }

    /// @brief Оператор проверки на неравенство.
    /// @param a Первый аргумент операции сравнения.
    /// @param b Второй аргумент операции сравнения.
    /// @retval true если a != b.
    /// @retval false если a == b.
    inline friend bool operator!=(const IPAddress& a,
                                  const IPAddress& b) noexcept
    {
        return !(a == b);
    }

    /// @brief Оператор проверки на знак '<'.
    /// @param a Первый аргумент операции сравнения.
    /// @param b Второй аргумент операции сравнения.
    /// @retval true если a < b.
    /// @retval false если a >= b.
    inline friend bool operator<(const IPAddress& a,
                                 const IPAddress& b) noexcept
    {
        if (a.type_ < b.type_)
            return true;
        if (a.type_ > b.type_)
            return false;
        if (a.type_ == IPv6)
            return a.ipv6_ < b.ipv6_;
        return a.ipv4_ < b.ipv4_;
    }

    /// @brief Оператор проверки на знак '>'.
    /// @param a Первый аргумент операции сравнения.
    /// @param b Второй аргумент операции сравнения.
    /// @retval true если a > b.
    /// @retval false если a <= b.
    inline friend bool operator>(const IPAddress& a,
                                 const IPAddress& b) noexcept
    {
        return b < a;
    }

    /// @brief Оператор проверки на знак '<='.
    /// @param a Первый аргумент операции сравнения.
    /// @param b Второй аргумент операции сравнения.
    /// @retval true если a <= b.
    /// @retval false если a > b.
    inline friend bool operator<=(const IPAddress& a,
                                  const IPAddress& b) noexcept
    {
        return !(b < a);
    }

    /// @brief Оператор проверки на знак '>='.
    /// @param a Первый аргумент операции сравнения.
    /// @param b Второй аргумент операции сравнения.
    /// @retval true если a >= b.
    /// @retval false если a < b.
    inline friend bool operator>=(const IPAddress& a,
                                  const IPAddress& b) noexcept
    {
        return !(a < b);
    }

    /// @brief Статический метод получения произвольного (ANY) IP-адреса.
    /// @return Объект класса IP-адреса.
    inline static IPAddress any() noexcept
    {
        return IPAddress();
    }

private:
    /// @brief Тип используемого адреса.
    enum
    {
        IPv4, ///< Тип IPv4
        IPv6  ///< Тип IPv6
    } type_;

    IPv4Address ipv4_; ///< Агрегированный класс адреса IPv4.
    IPv6Address ipv6_; ///< Агрегированный класс адреса IPv6.
};

} // namespace snet::network

template <> struct std::hash<snet::network::IPAddress>
{
    std::size_t operator()(const snet::network::IPAddress& addr) const noexcept
    {
        return addr.isIPv4()
                   ? std::hash<snet::network::IPv4Address>()(addr.toIPv4())
                   : std::hash<snet::network::IPv6Address>()(addr.toIPv6());
    }
};

inline std::ostream& operator<<(std::ostream& os,
                                const snet::network::IPAddress& addr)
{
    auto s = addr.toString();
    os << s.value_or("invalid_addr");
    return os;
}
