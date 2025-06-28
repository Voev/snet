#pragma once
#include <snet/cpp_port/span.hpp>
#include <snet/crypto/pointers.hpp>

namespace snet::crypto::ext
{

CertExtPtr create(const int nid, cpp::span<uint8_t> value, bool critical = false);

cpp::span<const uint8_t> view(CertExt* extension);

} // namespace snet::crypto::ext