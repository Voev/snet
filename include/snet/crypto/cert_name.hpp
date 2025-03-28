#pragma once
#include <string>
#include <snet/crypto/typedefs.hpp>

namespace snet::crypto::name
{

bool isEqual(const CertName* a, const CertName* b);

std::string serialNumber(const CertName* name);

} // namespace snet::crypto::name