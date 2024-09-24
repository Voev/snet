#include <string>
#include <cstring>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include <netdb.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>

#include <snet/socket/resolver.hpp>
#include <snet/socket/types.hpp>

#include <snet/utils/error_code.hpp>
#include <snet/utils/error_code_exception.hpp>
#include <snet/utils/to_number.hpp>

using namespace snet::ip;
using namespace snet::utils;

namespace snet::socket
{

ResolverOptions::ResolverOptions()
    : bindable_(false)
    , nicNameAllowed_(false)
    , ipv6_(false)
    , portExpected_(false)
    , dnsAllowed_(false)
    , pathAllowed_(false)
{
}

ResolverOptions::~ResolverOptions()
{
}

ResolverOptions& ResolverOptions::bindable(bool value)
{
    bindable_ = value;
    return *this;
}

ResolverOptions& ResolverOptions::allowNicName(bool value)
{
    nicNameAllowed_ = value;
    return *this;
}

ResolverOptions& ResolverOptions::ipv6(bool value)
{
    ipv6_ = value;
    return *this;
}

ResolverOptions& ResolverOptions::expectPort(bool value)
{
    portExpected_ = value;

    return *this;
}

ResolverOptions& ResolverOptions::allowDns(bool value)
{
    dnsAllowed_ = value;
    return *this;
}

ResolverOptions& ResolverOptions::allowPath(bool value)
{
    pathAllowed_ = value;
    return *this;
}

bool ResolverOptions::bindable() const
{
    return bindable_;
}

bool ResolverOptions::allowNicName() const
{
    return nicNameAllowed_;
}

bool ResolverOptions::ipv6() const
{
    return ipv6_;
}

bool ResolverOptions::expectPort() const
{
    return portExpected_;
}

bool ResolverOptions::allowDns() const
{
    return dnsAllowed_;
}

bool ResolverOptions::allowPath() const
{
    return pathAllowed_;
}

/*
io_service service;
ip::tcp::resolver resolver(service);
ip::tcp::resolver::query query("www.yahoo.com", "80");
ip::tcp::resolver::iterator iter = resolver.resolve( query);
ip::tcp::endpoint ep = *iter;
std::cout << ep.address().to_string() << std::endl;
 */

Resolver::ConstIterator Resolver::resolve(const std::string& str,
                                          const ResolverOptions& options)
{
    std::string addr;
    std::uint16_t port;

    if (options.expectPort())
    {
        auto delim = str.find_last_of(':');
        if (delim == std::string::npos)
        {
            throw std::runtime_error("undefined port number: " + str);
        }

        addr = str.substr(0, delim);
        const std::string port_str = str.substr(delim + 1);

        if (port_str == "*")
        {
            if (options.bindable())
            {
                port = 0;
            }
            else
            {
                throw std::logic_error("not bindable option");
            }
        }
        else if (port_str == "0")
        {
            port = 0;
        }
        else
        {
            to_number(port_str, port);
        }
    }
    else
    {
        addr = str;
        port = 0;
    }

    if (options.allowPath())
    {
        const size_t pos = addr.find('/');
        if (pos != std::string::npos)
        {
            addr = addr.substr(0, pos);
        }
    }

    const size_t bracketsLen = 2;
    if (addr.size() >= bracketsLen && addr[0] == '[' &&
        addr[addr.size() - 1] == ']')
    {
        addr = addr.substr(1, addr.size() - bracketsLen);
    }

    if (options.bindable() && addr == "*")
    {
        auto family = options.ipv6() ? AF_INET : AF_INET6;
        hosts_.emplace_back(Endpoint(family, port));
    }
    else
    {
        HostEntry* entry = gethostbyname(addr.data());
        if (!entry)
        {
            throw ErrorCodeException(GetLastSystemError());
        }

        IPAddress ip;
        for (auto addrlistp = entry->h_addr_list; *addrlistp != nullptr;
             ++addrlistp)
        {
            IPAddress ip;
            if (entry->h_addrtype == AF_INET)
            {
                auto bytes =
                    std::span{(uint8_t*)*addrlistp,
                              (uint8_t*)*addrlistp + (size_t)entry->h_length};
                ip = IPv4Address(bytes);
                hosts_.emplace_back(Endpoint(ip, port));
            }
            else
            {
                auto bytes =
                    std::span{(uint8_t*)*addrlistp,
                              (uint8_t*)*addrlistp + (size_t)entry->h_length};
                ip = IPv6Address(bytes);
                hosts_.emplace_back(Endpoint(ip, port));
            }
        }
    }

    return hosts_.begin();
}

Resolver::ConstIterator Resolver::end() const
{
    return hosts_.end();
}

} // namespace snet::socket