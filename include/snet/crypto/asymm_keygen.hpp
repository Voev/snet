#pragma once
#include <string_view>
#include <snet/crypto/pointers.hpp>

namespace snet::crypto::akey
{

namespace rsa
{

KeyPtr generate(size_t bits, OSSL_LIB_CTX* libctx = nullptr, const char* propq = nullptr);

} // namespace rsa

namespace ec
{

KeyPtr generate(std::string_view groupName, OSSL_LIB_CTX* libctx = nullptr,
                const char* propq = nullptr);

} // namespace ec

} // namespace snet::crypto::akey
