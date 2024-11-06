#include <snet/tls/secret_node.hpp>
#include <snet/utils/exception.hpp>

namespace snet::tls
{

SecretNode::SecretNode() = default;

SecretNode::~SecretNode() = default;

void SecretNode::setSecret(const Type type, const Secret& secret)
{
    utils::ThrowIfFalse(type >= MasterSecret && type < SecretTypesCount,
                        "invalid secret type");

    secrets_[type].resize(secret.size());
    std::copy(secret.begin(), secret.end(), secrets_[type].begin());
}

const Secret& SecretNode::getSecret(const Type type) const
{
    utils::ThrowIfFalse(type >= MasterSecret && type < SecretTypesCount,
                        "invalid secret type");

    return secrets_[type];
}

bool SecretNode::isValid(const ProtocolVersion version) const
{
    if (version == ProtocolVersion::TLSv1_3)
    {
        return !secrets_[SecretNode::ClientHandshakeTrafficSecret].empty() &&
               !secrets_[SecretNode::ServerHandshakeTrafficSecret].empty() &&
               !secrets_[SecretNode::ClientTrafficSecret].empty() &&
               !secrets_[SecretNode::ServerTrafficSecret].empty();
    }
    else if (version <= ProtocolVersion::TLSv1_2)
    {
        return !secrets_[SecretNode::MasterSecret].empty();
    }
    return false;
}

} // namespace snet::tls