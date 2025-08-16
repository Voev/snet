
#pragma once
#include <string>
#include <snet/crypto/pointers.hpp>
#include <casket/utils/noncopyable.hpp>

namespace snet::crypto
{

class CertNameBuilder final : casket::NonCopyable
{
public:
    static X509NamePtr fromString(const std::string& DN);

public:
    CertNameBuilder();

    ~CertNameBuilder() = default;

    void reset();

    CertNameBuilder& addEntry(const std::string& field, const std::string& value);

    X509NamePtr build();

    X509Name* name()
    {
        return name_;
    }

private:
    X509NamePtr name_;
};

} // namespace snet::crypto