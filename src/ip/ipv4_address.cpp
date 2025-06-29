#include <cassert>
#include <cstring>
#include <limits>

#include <snet/ip/ipv4_address.hpp>

#include <snet/utils/endianness.hpp>
#include <casket/utils/error_code.hpp>
#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::ip
{

IPv4Address::IPv4Address() noexcept
    : addr_{}
{
    addr_.s_addr = 0;
}

IPv4Address::IPv4Address(std::uint32_t addr) noexcept
    : addr_{}
{
    addr_.s_addr = utils::be_to_host(addr);
}

IPv4Address::IPv4Address(cpp::span<const std::uint8_t> bytes)
    : addr_{}
{
    assert(bytes.size_bytes() == kBytesCount);
    std::memcpy(&addr_.s_addr, bytes.data(), bytes.size_bytes());
}

IPv4Address::IPv4Address(std::string_view str)
    : addr_{}
{
    if (inet_pton(AF_INET, str.data(), &addr_.s_addr) <= 0)
    {
        auto ec = GetLastSystemError();
        if (!ec)
            ec = std::make_error_code(std::errc::invalid_argument);
        throw SystemError(ec);
    }
}

IPv4Address::~IPv4Address() = default;

IPv4Address::IPv4Address(const IPv4Address& other) noexcept
    : addr_(other.addr_)
{
}

IPv4Address::IPv4Address(IPv4Address&& other) noexcept
    : addr_(other.addr_)
{
}

IPv4Address& IPv4Address::operator=(const IPv4Address& other) noexcept
{
    addr_ = other.addr_;
    return *this;
}

IPv4Address& IPv4Address::operator=(IPv4Address&& other) noexcept
{
    addr_ = other.addr_;
    return *this;
}

bool IPv4Address::operator==(const IPv4Address& rhs) const noexcept
{
    return toUint() == rhs.toUint();
}

bool IPv4Address::operator!=(const IPv4Address& rhs) const noexcept
{
    return toUint() != rhs.toUint();
}

bool IPv4Address::operator<(const IPv4Address& rhs) const noexcept
{
    return toUint() < rhs.toUint();
}

bool IPv4Address::operator>(const IPv4Address& rhs) const noexcept
{
    return toUint() > rhs.toUint();
}

bool IPv4Address::operator<=(const IPv4Address& rhs) const noexcept
{
    return toUint() <= rhs.toUint();
}

bool IPv4Address::operator>=(const IPv4Address& rhs) const noexcept
{
    return toUint() >= rhs.toUint();
}

IPv4Address IPv4Address::operator&(const IPv4Address& mask) const
{
    return IPv4Address(utils::be_to_host(addr_.s_addr & mask.addr_.s_addr));
}

IPv4Address IPv4Address::operator|(const IPv4Address& mask) const
{
    return IPv4Address(utils::be_to_host(addr_.s_addr | mask.addr_.s_addr));
}

IPv4Address IPv4Address::operator~() const
{
    return IPv4Address(utils::be_to_host(~addr_.s_addr));
}

IPv4Address::operator uint32_t() const
{
    return toUint();
}

std::uint32_t IPv4Address::toUint() const
{
    return utils::host_to_be(addr_.s_addr);
}

std::string IPv4Address::toString() const
{
    char addrStr[INET_ADDRSTRLEN];
    auto addr = inet_ntop(AF_INET, &addr_.s_addr, addrStr, sizeof(addrStr));
    if (addr == nullptr)
    {
        throw SystemError(GetLastSystemError());
    }
    return addr;
}

bool IPv4Address::isLoopback() const noexcept
{
    return (toUint() & 0xFF000000) == 0x7F000000;
}

bool IPv4Address::isMulticast() const noexcept
{
    return (toUint() & 0xF0000000) == 0xE0000000;
}

bool IPv4Address::isBroadcast() const noexcept
{
    return (toUint() & 0xFFFFFFFF) == 0xFFFFFFFF;
}

bool IPv4Address::isUnicast() const noexcept
{
    return !isMulticast() && !isBroadcast();
}

bool increment(IPv4Address& addr)
{
    uint32_t addr_int = utils::be_to_host<uint32_t>(addr.toUint());
    bool reached_end = ++addr_int == std::numeric_limits<uint32_t>::max();
    addr = IPv4Address(utils::be_to_host<uint32_t>(addr_int));
    return reached_end;
}

bool decrement(IPv4Address& addr)
{
    uint32_t addrUint = utils::be_to_host<uint32_t>(addr.toUint());
    bool reachedEnd = --addrUint == 0;
    addr = IPv4Address(utils::be_to_host<uint32_t>(addrUint));
    return reachedEnd;
}

IPv4Address any() noexcept
{
    return IPv4Address();
}

std::optional<IPv4Address> IPv4Address::fromString(std::string_view str)
{
    std::uint8_t addr[kBytesCount];
    if (inet_pton(AF_INET, str.data(), addr) <= 0)
    {
        return std::nullopt;
    }
    return IPv4Address(addr);
}

} // namespace snet::ip
