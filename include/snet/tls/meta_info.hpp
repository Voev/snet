#pragma once
#include <snet/tls/version.hpp>
#include <snet/tls/cipher_suite.hpp>

namespace snet::tls
{

struct MetaInfo final
{
    ProtocolVersion version;
    const CipherSuite* cipherSuite{nullptr};
};

} // 