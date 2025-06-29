#pragma once
#include <snet/ip/types.hpp>

namespace snet::ip
{

class IPv6Address final
{
public:
    static constexpr std::size_t kBytesCount{16};
    typedef uint8_t* iterator;
    typedef const uint8_t* const_iterator;

    IPv6Address() noexcept;

    ~IPv6Address();

    explicit IPv6Address(nonstd::span<const std::uint8_t> bytes);
    
    explicit IPv6Address(std::string_view str);

    IPv6Address(const IPv6Address& other) noexcept;

    IPv6Address(IPv6Address&& other) noexcept;

    IPv6Address& operator=(const IPv6Address& other) noexcept;

    IPv6Address& operator=(IPv6Address&& other) noexcept;

    bool operator==(const IPv6Address& rhs) const noexcept;

    bool operator!=(const IPv6Address& rhs) const noexcept;

    bool operator<(const IPv6Address& rhs) const noexcept;

    bool operator>(const IPv6Address& rhs) const noexcept;

    bool operator<=(const IPv6Address& rhs) const noexcept;

    bool operator>=(const IPv6Address& rhs) const noexcept;

    IPv6Address operator&(const IPv6Address& rhs) const noexcept;

    IPv6Address operator|(const IPv6Address& rhs) const noexcept;

    IPv6Address operator~() const noexcept;

    iterator begin();

    const_iterator begin() const;
    
    iterator end();

    const_iterator end() const;

    std::string toString() const;

    bool isLoopback() const noexcept;

    bool isMulticast() const noexcept;

    static IPv6Address any() noexcept;

    static std::optional<IPv6Address> fromString(std::string_view str);

private:
    In6AddrType addr_;
};

} // namespace snet::ip

inline std::ostream& operator<<(std::ostream& os, const snet::ip::IPv6Address& addr)
{
    os << addr.toString();
    return os;
}

template <>
struct std::hash<snet::ip::IPv6Address>
{
    std::size_t operator()(const snet::ip::IPv6Address& addr) const noexcept
    {
        std::size_t output = snet::ip::IPv6Address::kBytesCount;
        snet::ip::IPv6Address::const_iterator iter = addr.begin();
        for (; iter != addr.end(); ++iter)
        {
            output ^= *iter + 0x9e3779b9 + (output << 6) + (output >> 2);
        }
        return output;
    }
};
