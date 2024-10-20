#pragma once
#include <string>
#include <string_view>
#include <span>
#include <vector>

namespace snet::utils
{

std::string hexlify(std::span<const uint8_t> in);

std::vector<uint8_t> unhexlify(std::string_view in);

} // namespace snet::utils