#pragma once
#include <casket/nonstd/span.hpp>
#include <snet/crypto/pointers.hpp>

namespace snet::crypto
{

class X509Extension final
{
public:
    X509ExtPtr create(const int nid, nonstd::span<uint8_t> value, bool critical = false);

    nonstd::span<const uint8_t> view(X509Ext* extension);
};

} // namespace snet::crypto