#pragma once
#include <queue>
#include <snet/tls/record.hpp>

namespace snet::tls
{

using RecordQueue = std::queue<Record*>;

}