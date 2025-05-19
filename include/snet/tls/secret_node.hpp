/// @file
/// @brief Declaration of the SecretNode class.

#pragma once
#include <array>
#include <vector>
#include <cstdint>
#include <snet/tls/version.hpp>

namespace snet::tls
{

using Secret = std::vector<uint8_t>;

/// @brief Class representing a secret node.
class SecretNode final
{
public:
    /// @brief Enumeration of secret types.
    enum Type
    {
        MasterSecret = 0,
        ClientEarlyTrafficSecret,
        ClientHandshakeTrafficSecret,
        ServerHandshakeTrafficSecret,
        ClientApplicationTrafficSecret,
        ServerApplicationTrafficSecret,
        SecretTypesCount
    };

    /// @brief Default constructor.
    SecretNode();

    /// @brief Destructor.
    ~SecretNode() noexcept;

    /// @brief Copy constructor.
    /// @param other Constant reference to the secret node.
    SecretNode(const SecretNode& other) = default;

    /// @brief Move constructor.
    /// @param other rvalue reference to the secret node.
    SecretNode(SecretNode&& other) noexcept = default;

    /// @brief Copy assignment operator.
    /// @param other Constant reference to the secret node.
    SecretNode& operator=(const SecretNode& other) = default;

    /// @brief Move assignment operator.
    /// @param other rvalue reference to the secret node.
    SecretNode& operator=(SecretNode&& other) noexcept = default;

    /// @brief Sets a secret of a specific type.
    /// @param type The type of the secret.
    /// @param secret The secret to set.
    void setSecret(const Type type, const Secret& secret);

    /// @brief Gets a secret of a specific type.
    /// @param type The type of the secret.
    /// @return The secret of the specified type.
    const Secret& getSecret(const Type type) const;

    /// @brief Checks if the secret node is valid for a specific protocol version.
    /// @param version The protocol version.
    /// @return True if the secret node is valid, false otherwise.
    bool isValid(const ProtocolVersion version) const;

private:
    std::array<Secret, SecretTypesCount> secrets_;
};

} // namespace snet::tls

