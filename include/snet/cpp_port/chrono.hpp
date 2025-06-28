#pragma once
#include <chrono>

namespace cpp
{

using chrono_years = std::chrono::duration<int64_t, std::ratio<31556952>>;

}