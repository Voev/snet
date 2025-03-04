#pragma once

#define SNET_SYMBOL_EXPORT __attribute__((visibility("default")))

#define SNET_DLL_SELECTANY __attribute__((weak))

#define SNET_DLL_SECTION(SectionName, Permissions)                                                 \
    static_assert(sizeof(#SectionName) < 10,                                                       \
                  "Some platforms require section names to be at most 8 bytes");                   \
    __attribute__((section(#SectionName)))

#define SNET_DLL_ALIAS_SECTIONED(FunctionOrVar, AliasName, SectionName)                            \
    namespace _autoaliases                                                                         \
    {                                                                                              \
    extern "C" SNET_SYMBOL_EXPORT const void* AliasName;                                           \
    SNET_DLL_SECTION(SectionName, read)                                                            \
    SNET_DLL_SELECTANY const void* AliasName =                                                     \
        reinterpret_cast<const void*>(reinterpret_cast<intptr_t>(&FunctionOrVar));                 \
    }

#define SNET_DLL_ALIAS(FunctionOrVar, AliasName)                                                   \
    SNET_DLL_ALIAS_SECTIONED(FunctionOrVar, AliasName, snet)

inline void foo()
{
}