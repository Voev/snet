#pragma once
#include <snet/layers/l3/types.hpp>
#include <casket/nonstd/string_view.hpp>
#include <casket/nonstd/optional.hpp>

namespace snet::layers
{

class IPv4Address final
{
public:
    static constexpr std::size_t kBytesCount = 4;

    IPv4Address() noexcept;

    explicit IPv4Address(std::uint32_t addr) noexcept;

    explicit IPv4Address(nonstd::span<const std::uint8_t> bytes);

    explicit IPv4Address(nonstd::string_view str);

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

    uint32_t toHost() const;

    uint32_t toNetwork() const;

    std::string toString() const;

    const uint8_t* asData() const noexcept
    {
        return reinterpret_cast<const uint8_t*>(&addr_.s_addr);
    }

    bool isLoopback() const noexcept;

    bool isMulticast() const noexcept;

    bool isBroadcast() const noexcept;

    bool isUnicast() const noexcept;

    static IPv4Address any() noexcept;

    static nonstd::optional<IPv4Address> fromString(nonstd::string_view str);

    IPv4Address fromNetwork(uint32_t addrBE) noexcept;

private:
    InAddrType addr_; // BE
};

} // namespace snet::layers

inline std::ostream& operator<<(std::ostream& os, const snet::layers::IPv4Address& addr)
{
    os << addr.toString();
    return os;
}

template <>
struct std::hash<snet::layers::IPv4Address>
{
    std::size_t operator()(const snet::layers::IPv4Address& addr) const noexcept
    {
        return std::hash<std::uint32_t>()(addr.toHost());
    }
};
