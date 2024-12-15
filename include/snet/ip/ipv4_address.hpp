#pragma once
#include <snet/ip/types.hpp>

namespace snet::ip
{

class IPv4Address final
{
public:
    static constexpr std::size_t kBytesCount = 4;

    IPv4Address() noexcept;

    explicit IPv4Address(std::uint32_t addr) noexcept;

    explicit IPv4Address(std::span<const std::uint8_t> bytes);

    explicit IPv4Address(std::string_view str);

    ~IPv4Address();

    IPv4Address(const IPv4Address& other) noexcept;

    IPv4Address(IPv4Address&& other) noexcept;

    IPv4Address& operator=(const IPv4Address& other) noexcept;

    IPv4Address& operator=(IPv4Address&& other) noexcept;

    bool operator==(const IPv4Address& rhs) const noexcept;

    bool operator!=(const IPv4Address& rhs) const noexcept;

    bool operator<(const IPv4Address& rhs) const noexcept;

    bool operator>(const IPv4Address& rhs) const noexcept;

    bool operator<=(const IPv4Address& rhs) const noexcept;

    bool operator>=(const IPv4Address& rhs) const noexcept;

    IPv4Address operator&(const IPv4Address& mask) const;

    IPv4Address operator|(const IPv4Address& mask) const;

    IPv4Address operator~() const;

    operator uint32_t() const;

    std::uint32_t toUint() const;

    std::string toString() const;

    bool isLoopback() const noexcept;

    bool isMulticast() const noexcept;

    bool isBroadcast() const noexcept;

    bool isUnicast() const noexcept;

    static IPv4Address any() noexcept;

    static std::optional<IPv4Address> fromString(std::string_view str);

private:
    InAddrType addr_;
};

} // namespace snet::ip

inline std::ostream& operator<<(std::ostream& os, const snet::ip::IPv4Address& addr)
{
    os << addr.toString();
    return os;
}

template <>
struct std::hash<snet::ip::IPv4Address>
{
    std::size_t operator()(const snet::ip::IPv4Address& addr) const noexcept
    {
        return std::hash<std::uint32_t>()(addr.toUint());
    }
};
