#pragma once
#include <cstdint>
#include <string>
#include <casket/nonstd/optional.hpp>
#include <casket/nonstd/span.hpp>
#include <casket/nonstd/string_view.hpp>

namespace snet::layers
{

struct InAddrType
{
    uint32_t s_addr;
};

struct In6AddrType
{
    union
    {
        uint8_t u6_addr8[16];
        uint16_t u6_addr16[8];
        uint32_t u6_addr32[4];
    } in6_u;
};

#define as_bytes in6_u.u6_addr8
#define as_words in6_u.u6_addr16
#define as_dwords in6_u.u6_addr32

} // namespace snet::layers