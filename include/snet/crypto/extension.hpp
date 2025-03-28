#pragma once
#include <span>
#include <snet/crypto/pointers.hpp>

namespace snet::crypto::ext
{

CertExtPtr create(const int nid, std::span<uint8_t> value, bool critical = false);

std::span<const uint8_t> view(CertExt* extension);

} // namespace snet::crypto::ext