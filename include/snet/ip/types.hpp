#pragma once
#include <arpa/inet.h>

#include <cstdint>
#include <optional>
#include <casket/nonstd/span.hpp>
#include <string>
#include <string_view>

namespace snet::ip
{

typedef in_addr InAddrType;
typedef in6_addr In6AddrType;

} // namespace snet::ip