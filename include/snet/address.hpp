#pragma once
#include <openssl/bio.h>
#include <stdexcept>
#include <string>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>

class Address
{
  public:
    Address()
        : addr_(BIO_ADDR_new())
    {
        if (!addr_)
        {
            throw std::bad_alloc();
        }
    }

    virtual ~Address()
    {
        BIO_ADDR_free(addr_);
    }

    BIO_ADDR* Get0() const
    {
        return addr_;
    }

    std::string ToString() const
    {
        std::string str{};
        char* hostname = BIO_ADDR_hostname_string(addr_, 1);
        char* service = BIO_ADDR_service_string(addr_, 1);
        str += hostname;
        str += ":";
        str += service;
        OPENSSL_free(hostname);
        OPENSSL_free(service);
        return str;
    }

  private:
    Address(const Address&) = delete;
    Address(Address&&) = delete;
    Address& operator=(const Address&) = delete;
    Address& operator=(Address&&) = delete;

  protected:
    BIO_ADDR* addr_{nullptr};
};

class AddressIPv4 final : public Address
{
  public:
    AddressIPv4(const std::string& ip, uint16_t port)
    {
        struct in_addr inaddr;
        int family = AF_INET;
        inet_pton(family, ip.c_str(), &inaddr);
        BIO_ADDR_rawmake(addr_, family, &inaddr, sizeof(inaddr), htons(port));
    }
};

class AddressIPv6 final : public Address
{
  public:
    AddressIPv6(const std::string& ip, uint16_t port)
    {
        struct in6_addr in6addr;
        int family = AF_INET6;
        inet_pton(family, ip.c_str(), &in6addr);
        BIO_ADDR_rawmake(addr_, family, &in6addr, sizeof(in6addr), htons(port));
    }
};