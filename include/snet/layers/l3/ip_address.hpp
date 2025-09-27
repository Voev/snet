#pragma once
#include <snet/layers/l3/ipv4_address.hpp>
#include <snet/layers/l3/ipv6_address.hpp>

namespace snet::layers
{

class IPAddress final
{
public:
    enum Type
    {
        IPv4,
        IPv6
    };

    IPAddress(Type type = IPv4) noexcept;

    IPAddress(const IPv4Address& addr) noexcept;

    IPAddress(const IPv6Address& addr) noexcept;

    ~IPAddress();

    IPAddress(const IPAddress& other) noexcept;

    IPAddress(IPAddress&& other) noexcept;

    IPAddress& operator=(const IPAddress& other) noexcept;

    IPAddress& operator=(IPAddress&& other) noexcept;

    IPAddress& operator=(const IPv4Address& other) noexcept;

    IPAddress& operator=(const IPv6Address& other) noexcept;

    std::string toString() const;

    bool isIPv4() const noexcept;

    bool isIPv6() const noexcept;

    IPv4Address toIPv4() const;

    IPv6Address toIPv6() const;

    bool operator==(const IPAddress& rhs) const noexcept;

    bool operator!=(const IPAddress& rhs) const noexcept;

    bool operator<(const IPAddress& rhs) const noexcept;

    bool operator>(const IPAddress& rhs) const noexcept;

    bool operator<=(const IPAddress& rhs) const noexcept;

    bool operator>=(const IPAddress& rhs) const noexcept;

    static IPAddress any(Type type = IPv4) noexcept;

    static std::optional<IPAddress> fromString(const char* str);

private:
    Type type_;

    IPv4Address ipv4_;
    IPv6Address ipv6_;
};

} // namespace snet::layers

inline std::ostream& operator<<(std::ostream& os, const snet::layers::IPAddress& addr)
{
    os << addr.toString();
    return os;
}

template <>
struct std::hash<snet::layers::IPAddress>
{
    std::size_t operator()(const snet::layers::IPAddress& addr) const noexcept
    {
        return addr.isIPv4() ? std::hash<snet::layers::IPv4Address>()(addr.toIPv4())
                             : std::hash<snet::layers::IPv6Address>()(addr.toIPv6());
    }
};
