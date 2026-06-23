#pragma once
#include <string>
#include <snet/crypto/pointers.hpp>

namespace snet::crypto
{

class CertSelfSigned
{
public:
    static X509CertPtr generate(Key* privateKey, const std::string& dn);
};

} // namespace snet::crypto