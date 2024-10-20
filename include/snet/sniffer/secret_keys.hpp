#pragma once
#include <array>
#include <vector>
#include <cstdint>

namespace snet::sniffer
{

using Secret = std::vector<uint8_t>;
class SecretKeys
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

    SecretKeys();

    ~SecretKeys() noexcept;

    void setSecret(const Type type, const Secret& secret);

    const Secret& getSecret(const Type type) const;

private:
    std::array<Secret, SecretTypesCount> secrets_;
};

} // namespace snet::sniffer

