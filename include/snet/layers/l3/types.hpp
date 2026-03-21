#pragma once
#include <arpa/inet.h>

#include <cstdint>
#include <string>
#include <casket/nonstd/optional.hpp>
#include <casket/nonstd/span.hpp>
#include <casket/nonstd/string_view.hpp>

namespace snet::layers
{

typedef in_addr InAddrType;
typedef in6_addr In6AddrType;

} // namespace snet::layers