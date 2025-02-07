/// @file
/// @brief Declaration of functions for loading and deserializing private keys.

#pragma once
#include <span>
#include <snet/tls/types.hpp>

namespace snet::tls
{

/// @brief Loads a key from a storage
///
/// @param uri URI to retrieve the key from the storage
/// @param meth UI_METHOD implementing the procedures to access the storage
/// @param data Additional data for @p meth
///
/// @return Returns a pointer to the key
EvpPkeyPtr LoadPrivateKey(const std::string& uri, const UI_METHOD* meth, void* data);

/// @brief Loads a key from a storage
///
/// @param uri URI to retrieve the key from the storage
///
/// @return Returns a pointer to the key
EvpPkeyPtr LoadPrivateKey(const std::string& uri);

/// @brief Deserializes a private key from a buffer
///
/// @param buffer The buffer containing the serialized key
///
/// @return Returns a pointer to the deserialized key
EvpPkeyPtr DeserializePrivateKey(std::span<const uint8_t> buffer);

} // namespace snet::tls