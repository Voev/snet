#pragma once
#include <filesystem>
#include <vector>
#include <string>
#include <span>
#include <snet/crypto/pointers.hpp>

namespace snet::crypto::akey
{

KeyPtr shallowCopy(Key* key);

KeyPtr deepCopy(Key* key);

bool isAlgorithm(const Key* key, std::string_view alg);

bool isEqual(const Key* a, const Key* b);

KeyPtr fromStorage(KeyType keyType, const std::string& uri);

KeyPtr fromStorage(KeyType keyType, const std::string& uri, const UiMethod* meth,
                              void* data);

KeyPtr fromFile(KeyType keyType, const std::filesystem::path& path);

KeyPtr fromBio(KeyType keyType, Bio* in, Encoding inEncoding);

void toBio(KeyType keyType, Key* key, Bio* bio, Encoding encoding = Encoding::PEM);

std::vector<uint8_t> getEncodedPublicKey(const Key* key);

void setEncodedPublicKey(Key* key, std::span<const uint8_t> value);
} // namespace snet::crypto::akey