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

#include <casket/utils/error_code.hpp>
#include <casket/utils/exception.hpp>
#include <casket/utils/to_number.hpp>

using namespace snet::ip;
using namespace casket;

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

Resolver::ConstIterator Resolver::resolve(const std::string& str, const ResolverOptions& options)
{
    std::string addr;
    std::uint16_t port;

    if (options.expectPort())
    {
        auto delim = str.find_last_of(':');
        if (delim == std::string::npos)
        {
            throw RuntimeError("undefined port number: " + str);
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
    if (addr.size() >= bracketsLen && addr[0] == '[' && addr[addr.size() - 1] == ']')
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
        struct addrinfo hints{};
        hints.ai_family = options.ipv6() ? AF_INET6 : AF_INET;

        if (options.bindable())
            hints.ai_flags |= AI_PASSIVE;

        struct addrinfo* result = nullptr;
        int error = getaddrinfo(addr.c_str(), nullptr, &hints, &result);
        if (error != 0)
        {
            throw SystemError(GetLastSystemError());
        }

        for (auto ptr = result; ptr != nullptr; ptr = ptr->ai_next)
        {
            Endpoint ep;
            std::memcpy(ep.data(), ptr->ai_addr, ptr->ai_addrlen);
            ep.port(port);
            hosts_.emplace_back(std::move(ep));
        }
    }

    return hosts_.begin();
}

Resolver::ConstIterator Resolver::end() const
{
    return hosts_.end();
}

} // namespace snet::socket