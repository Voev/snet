#include <openssl/rand.h>
#include <snet/crypto/rand.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::crypto
{

void Rand::seed(const uint8_t* entropy, const size_t entropySize)
{
    RAND_seed(entropy, entropySize < INT_MAX ? static_cast<int>(entropySize) : INT_MAX);
}

void Rand::generate(uint8_t* random, const size_t randomSize)
{
    ThrowIfFalse(0 < RAND_bytes(random, randomSize < INT_MAX ? static_cast<int>(randomSize) : INT_MAX));
}

} // namespace snet::crypto