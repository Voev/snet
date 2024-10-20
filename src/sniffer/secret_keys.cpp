#include <snet/sniffer/secret_keys.hpp>
#include <snet/utils/exception.hpp>

namespace snet::sniffer
{

SecretKeys::SecretKeys() = default;

SecretKeys::~SecretKeys() = default;

void SecretKeys::setSecret(const Type type, const Secret& secret)
{
    utils::ThrowIfFalse(type >= MasterSecret && type < SecretTypesCount,
                        "invalid secret type");

    secrets_[type].resize(secret.size());
    std::copy(secret.begin(), secret.end(), secrets_[type].begin());
}

const Secret& SecretKeys::getSecret(const Type type) const
{
    utils::ThrowIfFalse(type >= MasterSecret && type < SecretTypesCount,
                        "invalid secret type");

    return secrets_[type];
}



} // namespace snet::sniffer