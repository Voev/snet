#pragma once
#include <array>
#include <vector>
#include <cstdint>
#include <snet/tls/version.hpp>

namespace snet::tls
{

using Secret = std::vector<uint8_t>;
class SecretNode
{
public:
    enum Type
    {
        MasterSecret = 0,
        ClientEarlyTrafficSecret,
        ClientHandshakeTrafficSecret,
        ServerHandshakeTrafficSecret,
        ClientTrafficSecret,
        ServerTrafficSecret,
        SecretTypesCount
    };

    SecretNode();

    ~SecretNode() noexcept;

    void setSecret(const Type type, const Secret& secret);

    const Secret& getSecret(const Type type) const;

    bool isValid(const ProtocolVersion version) const;

private:
    std::array<Secret, SecretTypesCount> secrets_;
};

} // namespace snet::tls

