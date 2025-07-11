
#pragma once
#include <string>
#include <snet/crypto/pointers.hpp>
#include <casket/utils/noncopyable.hpp>

namespace snet::crypto
{

class CertNameBuilder final : casket::NonCopyable
{
public:
    static CertNamePtr fromString(const std::string& DN);

public:
    CertNameBuilder();

    ~CertNameBuilder() = default;

    void reset();

    CertNameBuilder& addEntry(const std::string& field, const std::string& value);

    CertNamePtr build();

    CertName* name()
    {
        return name_;
    }

private:
    CertNamePtr name_;
};

} // namespace snet::crypto