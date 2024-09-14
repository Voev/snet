#pragma once
#include <string_view>

namespace snet::log
{

static constexpr std::string_view resetColor{"\x1B[0m"};

static constexpr std::string_view lRed{"\x1B[0;31m"};
static constexpr std::string_view bRed{"\x1B[1;31m"};

static constexpr std::string_view lGreen{"\x1B[0;32m"};
static constexpr std::string_view bGreen{"\x1B[1;32m"};

static constexpr std::string_view lYellow{"\x1B[0;33m"};
static constexpr std::string_view bYellow{"\x1B[1;33m"};

static constexpr std::string_view lBlue{"\x1B[0;34m"};
static constexpr std::string_view bBlue{"\x1B[1;34m"};

static constexpr std::string_view lPurple{"\x1B[0;35m"};
static constexpr std::string_view bPurple{"\x1B[1;35m"};

static constexpr std::string_view lCyan{"\x1B[0;36m"};
static constexpr std::string_view bCyan{"\x1B[1;36m"};

static constexpr std::string_view lWhite{"\x1B[0;37m"};
static constexpr std::string_view bWhite{"\x1B[1;37m"};

} // namespace snet::log