#pragma once

#define SNET_NAMESPACE_BEGIN namespace snet

#if __cplusplus >= 201703L
#define SNET_NAMESPACE_NESTED_BEGIN(ns1)                                                                               \
    namespace snet::ns1                                                                                                \
    {
#define SNET_NAMESPACE_NESTED_END(ns1) }
#else
#define SNET_NAMESPACE_NESTED_BEGIN(ns1)                                                                               \
    namespace snet                                                                                                     \
    {                                                                                                                  \
    namespace ns1                                                                                                      \
    {
#define SNET_NAMESPACE_NESTED_END(ns1)                                                                                 \
    }                                                                                                                  \
    }
#endif
