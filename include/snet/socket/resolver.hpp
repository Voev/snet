#pragma once
#include <list>
#include <snet/socket/endpoint.hpp>
#include <snet/socket/types.hpp>

namespace snet::socket
{

class ResolverOptions final
{
public:
    ResolverOptions();
    ~ResolverOptions();

    ResolverOptions& bindable(bool value);
    ResolverOptions& allowNicName(bool value);
    ResolverOptions& ipv6(bool value);
    ResolverOptions& expectPort(bool value);
    ResolverOptions& allowDns(bool value);
    ResolverOptions& allowPath(bool value);

    bool bindable() const;
    bool allowNicName() const;
    bool ipv6() const;
    bool expectPort() const;
    bool allowDns() const;
    bool allowPath() const;

private:
    bool bindable_;
    bool nicNameAllowed_;
    bool ipv6_;
    bool portExpected_;
    bool dnsAllowed_;
    bool pathAllowed_;
};

class Resolver
{
public:
    using Container = std::list<Endpoint>;
    using Iterator = Container::iterator;
    using ConstIterator = Container::const_iterator;

    Resolver() = default;
    ~Resolver() = default;

    ConstIterator resolve(const std::string& str, const ResolverOptions& options);
    ConstIterator end() const;

private:
    Container hosts_;
};

} // namespace snet::socket
