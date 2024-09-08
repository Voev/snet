#include <cassert>
#include <algorithm>
#include <snet/ip/ipv6_address.hpp>

#include <snet/utils/error_code.hpp>
#include <snet/utils/error_code_exception.hpp>

using namespace snet::utils;

namespace snet::ip
{

IPv6Address::IPv6Address() noexcept
    : addr_()
{
}

IPv6Address::~IPv6Address() = default;

IPv6Address::IPv6Address(std::span<const std::uint8_t> bytes)
{
    assert(bytes.size_bytes() == kBytesCount);
    std::copy(bytes.begin(), bytes.end(), std::begin(addr_.s6_addr));
}

IPv6Address::IPv6Address(std::string_view str)
{
    if (inet_pton(AF_INET6, str.data(), &addr_.s6_addr) <= 0)
    {
        auto ec = GetLastSystemError();
        if (!ec)
            ec = std::make_error_code(std::errc::invalid_argument);
        throw ErrorCodeException(ec);
    }
}

IPv6Address::IPv6Address(const IPv6Address& other) noexcept
    : addr_(other.addr_)
{
}

IPv6Address::IPv6Address(IPv6Address&& other) noexcept
    : addr_(other.addr_)
{
}

IPv6Address& IPv6Address::operator=(const IPv6Address& other) noexcept
{
    addr_ = other.addr_;
    return *this;
}

IPv6Address& IPv6Address::operator=(IPv6Address&& other) noexcept
{
    addr_ = other.addr_;
    return *this;
}

IPv6Address::iterator IPv6Address::begin()
{
    return addr_.s6_addr;
}

IPv6Address::const_iterator IPv6Address::begin() const
{
    return addr_.s6_addr;
}

IPv6Address::iterator IPv6Address::end()
{
    return addr_.s6_addr + kBytesCount;
}

IPv6Address::const_iterator IPv6Address::end() const
{
    return addr_.s6_addr + kBytesCount;
}

std::optional<IPv6Address> fromString(std::string_view str)
{
    std::uint8_t addr[IPv6Address::kBytesCount];
    if (inet_pton(AF_INET6, str.data(), addr) <= 0)
    {
        return std::nullopt;
    }
    return IPv6Address(addr);
}

bool IPv6Address::operator==(const IPv6Address& rhs) const noexcept
{
    return std::equal(begin(), end(), rhs.begin());
}

bool IPv6Address::operator!=(const IPv6Address& rhs) const noexcept
{
    return !(*this == rhs);
}

bool IPv6Address::operator<(const IPv6Address& rhs) const noexcept
{
    return std::lexicographical_compare(begin(), end(), rhs.begin(), rhs.end());
}

bool IPv6Address::operator>(const IPv6Address& rhs) const noexcept
{
    return rhs < *this;
}

bool IPv6Address::operator<=(const IPv6Address& rhs) const noexcept
{
    return !(rhs < *this);
}

bool IPv6Address::operator>=(const IPv6Address& rhs) const noexcept
{
    return !(*this < rhs);
}

IPv6Address IPv6Address::operator&(const IPv6Address& rhs) const noexcept
{
    IPv6Address result = *this;
    IPv6Address::iterator addressIter = result.begin();
    for (IPv6Address::const_iterator it = rhs.begin(); it != rhs.end();
         ++it, ++addressIter)
    {
        *addressIter = *addressIter & *it;
    }

    return result;
}

IPv6Address IPv6Address::operator|(const IPv6Address& rhs) const noexcept
{
    IPv6Address result = *this;
    IPv6Address::iterator addressIter = result.begin();
    for (IPv6Address::const_iterator it = rhs.begin(); it != rhs.end();
         ++it, ++addressIter)
    {
        *addressIter = *addressIter | *it;
    }

    return result;
}

IPv6Address IPv6Address::operator~() const noexcept
{
    IPv6Address result = *this;
    for (IPv6Address::iterator addressIter = result.begin();
         addressIter != result.end(); ++addressIter)
    {
        *addressIter = ~*addressIter;
    }

    return result;
}

std::string IPv6Address::toString() const
{
    char addrStr[INET6_ADDRSTRLEN];
    const auto addr = inet_ntop(AF_INET6, &addr_, addrStr, sizeof(addrStr));
    if (addr == nullptr)
    {
        throw ErrorCodeException(GetLastSystemError());
    }
    return addr;
}

bool IPv6Address::isLoopback() const noexcept
{
    return ((addr_.s6_addr[0] == 0) && (addr_.s6_addr[1] == 0) &&
            (addr_.s6_addr[2] == 0) && (addr_.s6_addr[3] == 0) &&
            (addr_.s6_addr[4] == 0) && (addr_.s6_addr[5] == 0) &&
            (addr_.s6_addr[6] == 0) && (addr_.s6_addr[7] == 0) &&
            (addr_.s6_addr[8] == 0) && (addr_.s6_addr[9] == 0) &&
            (addr_.s6_addr[10] == 0) && (addr_.s6_addr[11] == 0) &&
            (addr_.s6_addr[12] == 0) && (addr_.s6_addr[13] == 0) &&
            (addr_.s6_addr[14] == 0) && (addr_.s6_addr[15] == 1));
}

bool IPv6Address::isMulticast() const noexcept
{
    return (addr_.s6_addr[0] == 0xff);
}

IPv6Address IPv6Address::any() noexcept
{
    return IPv6Address();
}

} // namespace snet::ip

std::ostream& operator<<(std::ostream& os, const snet::ip::IPv6Address& addr)
{
    os << addr.toString();
    return os;
}