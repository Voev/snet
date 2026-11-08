/// @file
/// @brief Policy extracted from a ClientHello, used to build our own
///        ClientHello (for upstream) and ServerHello (for the client).

#pragma once

#include <casket/nonstd/string_view.hpp>
#include <casket/nonstd/span.hpp>

#include <snet/tls/version.hpp>

#include <snet/crypto/pointers.hpp>
#include <snet/crypto/group_params.hpp>
#include <snet/crypto/signature_scheme.hpp>

namespace snet::tls
{

class Session;
struct ServerHello;

struct ServerHelloPolicy final
{
    ProtocolVersion version;
    std::uint16_t suite;
    crypto::GroupParams group;
    nonstd::span<const std::uint8_t> sessionId;
    nonstd::span<const crypto::SignatureScheme> signatureAlgorithms;
    
    bool useEncryptThenMac = true;
    bool useExtendedMasterSecret = true;
    bool useSessionTicket = false;
    bool useRenegotiationInfo = false;

    static ServerHelloPolicy make(const ServerHello& src, const Session& processedOn) noexcept;
};

} // namespace snet::tls