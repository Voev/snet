#pragma once
#include <casket/nonstd/span.hpp>
#include <snet/crypto/pointers.hpp>

namespace snet::crypto::ext
{

CertExtPtr create(const int nid, nonstd::span<uint8_t> value, bool critical = false);

nonstd::span<const uint8_t> view(CertExt* extension);

} // namespace snet::crypto::ext