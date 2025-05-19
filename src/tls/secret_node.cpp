#include <snet/tls/secret_node.hpp>
#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

SecretNode::SecretNode()
{
}

SecretNode::~SecretNode() noexcept
{
}

void SecretNode::setSecret(const Type type, const Secret& secret)
{
    ThrowIfFalse(type >= MasterSecret && type < SecretTypesCount, "invalid secret type");

    secrets_[type].resize(secret.size());
    std::copy(secret.begin(), secret.end(), secrets_[type].begin());
}

const Secret& SecretNode::getSecret(const Type type) const
{
    ThrowIfFalse(type >= MasterSecret && type < SecretTypesCount, "invalid secret type");

    return secrets_[type];
}

bool SecretNode::isValid(const ProtocolVersion version) const
{
    if (version == ProtocolVersion::TLSv1_3)
    {
        return !secrets_[SecretNode::ClientHandshakeTrafficSecret].empty() &&
               !secrets_[SecretNode::ServerHandshakeTrafficSecret].empty() &&
               !secrets_[SecretNode::ClientApplicationTrafficSecret].empty() &&
               !secrets_[SecretNode::ServerApplicationTrafficSecret].empty();
    }
    else if (version <= ProtocolVersion::TLSv1_2)
    {
        return !secrets_[SecretNode::MasterSecret].empty();
    }
    return false;
}

} // namespace snet::tls