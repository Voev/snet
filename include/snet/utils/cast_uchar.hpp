#pragma once

namespace snet
{

inline const unsigned char* castToUchar(const char* value)
{
    return reinterpret_cast<const unsigned char*>(value);
}

inline const unsigned char* castToUchar(const unsigned char* value)
{
    return (value);
}

inline unsigned char* castToUchar(char* value)
{
    return reinterpret_cast<unsigned char*>(value);
}

inline unsigned char* castToUchar(unsigned char* value)
{
    return (value);
}

} // namespace snet