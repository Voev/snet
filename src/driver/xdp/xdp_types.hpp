#pragma once

#include <cstdint>

namespace snet::driver::xdp
{

constexpr uint32_t kDefaultBatchSize   = 64;
constexpr uint32_t kDefaultNumFrames   = 4096;
constexpr uint32_t kDefaultFillSize    = 2048;
constexpr uint32_t kDefaultCompSize    = 2048;
constexpr uint32_t kDefaultRxSize      = 2048;
constexpr uint32_t kDefaultTxSize      = 2048;
constexpr uint32_t kDefaultFrameSize   = 2048;
constexpr uint32_t kDefaultHeadroom    = 256;
constexpr uint32_t kDefaultMsgPoolSize = 1024;
constexpr uint32_t kMaxQueuesPerIface  = 64;
constexpr uint32_t kMaxEndpoints       = 64;

} // namespace snet::driver::xdp