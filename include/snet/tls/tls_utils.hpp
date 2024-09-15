#pragma once
#include <optional>
#include <string_view>
#include <snet/tls/types.hpp>

namespace snet::tls
{

std::optional<ProtocolVersion> ParseVersion(std::string_view str);

std::optional<ProtocolVersionRange> ParseVersionRange(std::string_view str);

} // namespace snet::tls