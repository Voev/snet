#pragma once
#include <snet/crypto/pointers.hpp>

namespace snet::crypto
{

class RsaAsymmKey final
{
public:
    static KeyPtr generate(size_t bits);
};

} // namespace snet::crypto