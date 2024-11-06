#pragma once
#include <optional>
#include <string_view>
#include <snet/tls/types.hpp>

namespace snet::tls
{

std::optional<VersionCode> ParseVersion(std::string_view str);

std::optional<VersionCodeRange> ParseVersionRange(std::string_view str);

} // namespace snet::tls