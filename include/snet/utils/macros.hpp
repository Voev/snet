#pragma once

#define SNET_LIKELY(x) __builtin_expect((x), 1)
#define SNET_UNLIKELY(x) __builtin_expect((x), 0)