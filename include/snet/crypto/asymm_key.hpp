#pragma once
#include <filesystem>
#include <vector>
#include <string>
#include <snet/crypto/pointers.hpp>
#include <casket/nonstd/span.hpp>

namespace snet::crypto
{

class AsymmKey
{
public:
    static KeyPtr shallowCopy(Key* key);

    static bool isAlgorithm(const Key* key, std::string_view alg);

    static bool isEqual(const Key* a, const Key* b);

    static KeyPtr fromStorage(KeyType keyType, const std::string& uri);

    static KeyPtr fromStorage(KeyType keyType, const std::string& uri, const UiMethod* meth, void* data);

    static KeyPtr fromFile(KeyType keyType, const std::filesystem::path& path);

    static KeyPtr fromBio(KeyType keyType, Bio* in, Encoding inEncoding);

    static void toBio(KeyType keyType, Key* key, Bio* bio, Encoding encoding = Encoding::PEM);

    static std::vector<uint8_t> getEncodedPublicKey(const Key* key);

    static void setEncodedPublicKey(Key* key, nonstd::span<const uint8_t> value);
};

} // namespace snet::crypto