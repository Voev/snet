#include <snet/tls/secret_node.hpp>

namespace snet::tls
{

bool SecretNode::isValid(const ProtocolVersion version) const noexcept
{
    if (version == ProtocolVersion::TLSv1_3)
    {
        return !clientHndTrafficSecret.empty() &&
               !serverHndTrafficSecret.empty() &&
               !clientAppTrafficSecret.empty() &&
               !serverAppTrafficSecret.empty();
    }
    else if (version <= ProtocolVersion::TLSv1_2)
    {
        return !masterSecret.empty();
    }
    return false;
}

} // namespace snet::tls