#include <iterator>
#include <snet/tls/extensions.hpp>

namespace snet::tls {

std::unique_ptr<Extension>
make_extension(stream::DataReader& reader, Extension_Code code, const Side from, const HandshakeType message_type) {
    
    (void)message_type;
    
    // This cast is safe because we read exactly a 16 bit length field for
    // the extension in Extensions::deserialize
    const uint16_t size = static_cast<uint16_t>(reader.remaining_bytes());
    switch (code) {
        case Extension_Code::ServerNameIndication:
            return std::make_unique<ServerNameIndicator>(reader, size);

        case Extension_Code::ApplicationLayerProtocolNegotiation:
            return std::make_unique<Application_Layer_Protocol_Notification>(reader, size, from);

        case Extension_Code::ClientCertificateType:
            return std::make_unique<Client_Certificate_Type>(reader, size, from);

        case Extension_Code::ServerCertificateType:
            return std::make_unique<Server_Certificate_Type>(reader, size, from);

        case Extension_Code::ExtendedMasterSecret:
            return std::make_unique<Extended_Master_Secret>(reader, size);

        case Extension_Code::RecordSizeLimit:
            return std::make_unique<Record_Size_Limit>(reader, size, from);

        case Extension_Code::EncryptThenMac:
            return std::make_unique<Encrypt_then_MAC>(reader, size);

        case Extension_Code::SupportedVersions:
            return std::make_unique<Supported_Versions>(reader, size, from);

        default:
            break;
    }

    return std::make_unique<Unknown_Extension>(code, reader, size);
}

void Extensions::add(std::unique_ptr<Extension> extn) {
    if (has(extn->type())) {
        throw std::runtime_error(
            "cannot add the same extension twice: " + std::to_string(static_cast<uint16_t>(extn->type())));
    }

    m_extensions.emplace_back(extn.release());
}

void Extensions::deserialize(stream::DataReader& reader, const Side from, const HandshakeType message_type) {
    if (reader.has_remaining()) {
        const uint16_t all_extn_size = reader.get_uint16_t();

        if (reader.remaining_bytes() != all_extn_size) {
            throw std::runtime_error("Bad extension size");
        }

        while (reader.has_remaining()) {
            const uint16_t extension_code = reader.get_uint16_t();
            const uint16_t extension_size = reader.get_uint16_t();

            const auto type = static_cast<Extension_Code>(extension_code);

            if (this->has(type)) {
                throw std::runtime_error("Peer sent duplicated extensions");
            }

            // TODO offer a function on reader that returns a byte range as a reference
            // to avoid this copy of the extension data
            const std::vector<uint8_t> extn_data = reader.get_fixed<uint8_t>(extension_size);
            stream::DataReader extn_reader("Extension", extn_data);
            this->add(make_extension(extn_reader, type, from, message_type));
            extn_reader.assert_done();
        }
    }
}

bool Extensions::contains_other_than(
    const std::set<Extension_Code>& allowed_extensions, const bool allow_unknown_extensions) const {
    const auto found = extension_types();

    std::vector<Extension_Code> diff;
    std::set_difference(
        found.cbegin(), found.end(), allowed_extensions.cbegin(), allowed_extensions.cend(), std::back_inserter(diff));

    if (allow_unknown_extensions) {
        // Go through the found unexpected extensions whether any of those
        // is known to this TLS implementation.
        const auto itr = std::find_if(diff.cbegin(), diff.cend(), [this](const auto ext_type) {
            const auto ext = get(ext_type);
            return ext;
        });

        // ... if yes, `contains_other_than` is true
        return itr != diff.cend();
    }

    return !diff.empty();
}

std::unique_ptr<Extension> Extensions::take(Extension_Code type) {
    const auto i =
        std::find_if(m_extensions.begin(), m_extensions.end(), [type](const auto& ext) { return ext->type() == type; });

    std::unique_ptr<Extension> result;
    if (i != m_extensions.end()) {
        std::swap(result, *i);
        m_extensions.erase(i);
    }

    return result;
}

std::set<Extension_Code> Extensions::extension_types() const {
    std::set<Extension_Code> offers;
    std::transform(
        m_extensions.cbegin(), m_extensions.cend(), std::inserter(offers, offers.begin()),
        [](const auto& ext) { return ext->type(); });
    return offers;
}

Unknown_Extension::Unknown_Extension(Extension_Code type, stream::DataReader& reader, uint16_t extension_size)
    : m_type(type)
    , m_value(reader.get_fixed<uint8_t>(extension_size)) {
}

ServerNameIndicator::ServerNameIndicator(stream::DataReader& reader, uint16_t extension_size) {
    /*
     * This is used by the server to confirm that it knew the name
     */
    if (extension_size == 0) {
        return;
    }

    uint16_t name_bytes = reader.get_uint16_t();

    if (name_bytes + 2 != extension_size) {
        throw std::runtime_error("Bad encoding of SNI extension");
    }

    while (name_bytes) {
        uint8_t name_type = reader.get_byte();
        name_bytes--;

        if (name_type == 0) {
            // DNS
            m_sni_host_name = reader.get_string(2, 1, 65535);
            name_bytes -= static_cast<uint16_t>(2 + m_sni_host_name.size());
        } else {
            // some other unknown name type, which we will ignore
            reader.discard_next(name_bytes);
            name_bytes = 0;
        }
    }
}

Application_Layer_Protocol_Notification::Application_Layer_Protocol_Notification(
    stream::DataReader& reader, uint16_t extension_size, Side from) {
    if (extension_size == 0) {
        return; // empty extension
    }

    const uint16_t name_bytes = reader.get_uint16_t();

    size_t bytes_remaining = extension_size - 2;

    if (name_bytes != bytes_remaining) {
        throw std::runtime_error("Bad encoding of ALPN extension, bad length field");
    }

    while (bytes_remaining) {
        const std::string p = reader.get_string(1, 0, 255);

        if (bytes_remaining < p.size() + 1) {
            throw std::runtime_error("Bad encoding of ALPN, length field too long");
        }

        if (p.empty()) {
            throw std::runtime_error("Empty ALPN protocol not allowed");
        }

        bytes_remaining -= (p.size() + 1);

        m_protocols.push_back(p);
    }

    // RFC 7301 3.1
    //    The "extension_data" field of the [...] extension is structured the
    //    same as described above for the client "extension_data", except that
    //    the "ProtocolNameList" MUST contain exactly one "ProtocolName".
    if (from == Side::Server && m_protocols.size() != 1) {
        throw std::runtime_error(
            "Server sent " + std::to_string(m_protocols.size()) + " protocols in ALPN extension response");
    }
}

std::string Application_Layer_Protocol_Notification::single_protocol() const {
    // BOTAN_STATE_CHECK(m_protocols.size() == 1);
    return m_protocols.front();
}

std::string certificate_type_to_string(Certificate_Type type) {
    switch (type) {
        case Certificate_Type::X509:
            return "X509";
        case Certificate_Type::RawPublicKey:
            return "RawPublicKey";
    }

    return "Unknown";
}

Certificate_Type certificate_type_from_string(const std::string& type_str) {
    if (type_str == "X509") {
        return Certificate_Type::X509;
    } else if (type_str == "RawPublicKey") {
        return Certificate_Type::RawPublicKey;
    } else {
        throw std::runtime_error("Unknown certificate type: " + type_str);
    }
}

Certificate_Type_Base::Certificate_Type_Base(std::vector<Certificate_Type> supported_cert_types)
    : m_certificate_types(std::move(supported_cert_types))
    , m_from(Side::Client) {
    utils::ThrowIfFalse(m_certificate_types.empty(), "at least one certificate type must be supported");
}

Client_Certificate_Type::Client_Certificate_Type(const Client_Certificate_Type& cct)
    : Certificate_Type_Base(cct) {
}

Server_Certificate_Type::Server_Certificate_Type(const Server_Certificate_Type& sct)
    : Certificate_Type_Base(sct) {
}

template <typename T>
bool contains(std::vector<T> const& v, T const& x) {
    return std::find(v.begin(), v.end(), x) != v.end();
}

Certificate_Type_Base::Certificate_Type_Base(
    const Certificate_Type_Base& certificate_type_from_client, const std::vector<Certificate_Type>& server_preference)
    : m_from(Side::Server) {
    // RFC 7250 4.2
    //    The server_certificate_type extension in the client hello indicates the
    //    types of certificates the client is able to process when provided by
    //    the server in a subsequent certificate payload. [...] With the
    //    server_certificate_type extension in the server hello, the TLS server
    //    indicates the certificate type carried in the Certificate payload.
    for (const auto server_supported_cert_type : server_preference) {
        if (contains(certificate_type_from_client.m_certificate_types, server_supported_cert_type)) {
            m_certificate_types.push_back(server_supported_cert_type);
            return;
        }
    }

    // RFC 7250 4.2 (2.)
    //    The server supports the extension defined in this document, but
    //    it does not have any certificate type in common with the client.
    //    Then, the server terminates the session with a fatal alert of
    //    type "unsupported_certificate".
    throw std::runtime_error("Failed to agree on certificate_type");
}

Certificate_Type_Base::Certificate_Type_Base(stream::DataReader& reader, uint16_t extension_size, Side from)
    : m_from(from) {
    if (extension_size == 0) {
        throw std::runtime_error("Certificate type extension cannot be empty");
    }

    if (from == Side::Client) {
        const auto type_bytes = reader.get_tls_length_value(1);
        if (static_cast<size_t>(extension_size) != type_bytes.size() + 1) {
            throw std::runtime_error("certificate type extension had inconsistent length");
        }
        std::transform(
            type_bytes.begin(), type_bytes.end(), std::back_inserter(m_certificate_types),
            [](const auto type_byte) { return static_cast<Certificate_Type>(type_byte); });
    } else {
        // RFC 7250 4.2
        //    Note that only a single value is permitted in the
        //    server_certificate_type extension when carried in the server hello.
        if (extension_size != 1) {
            throw std::runtime_error("Server's certificate type extension must be of length 1");
        }
        const auto type_byte = reader.get_byte();
        m_certificate_types.push_back(static_cast<Certificate_Type>(type_byte));
    }
}

void Certificate_Type_Base::validate_selection(const Certificate_Type_Base& from_server) const {
    utils::ThrowIfFalse(m_from == Side::Client, "invalid from");
    utils::ThrowIfFalse(from_server.m_from == Side::Server, "invalid from_server");

    // RFC 7250 4.2
    //    The value conveyed in the [client_]certificate_type extension MUST be
    //    selected from one of the values provided in the [client_]certificate_type
    //    extension sent in the client hello.
    if (!contains(m_certificate_types, from_server.selected_certificate_type())) {
        throw std::runtime_error(utils::format(
            "Selected certificate type was not offered: {}",
            certificate_type_to_string(from_server.selected_certificate_type())));
    }
}

Certificate_Type Certificate_Type_Base::selected_certificate_type() const {
    utils::ThrowIfFalse(m_from == Side::Server, "Invalid m_from");
    utils::ThrowIfFalse(m_certificate_types.size() == 1, "invalid certificate type");
    return m_certificate_types.front();
}

Extended_Master_Secret::Extended_Master_Secret(stream::DataReader& /*unused*/, uint16_t extension_size) {
    if (extension_size != 0) {
        throw std::runtime_error("Invalid extended_master_secret extension");
    }
}

Encrypt_then_MAC::Encrypt_then_MAC(stream::DataReader& /*unused*/, uint16_t extension_size) {
    if (extension_size != 0) {
        throw std::runtime_error("Invalid encrypt_then_mac extension");
    }
}

Supported_Versions::Supported_Versions(stream::DataReader& reader, uint16_t extension_size, Side from) {
    if (from == Side::Server) {
        if (extension_size != 2) {
            throw std::runtime_error("Server sent invalid supported_versions extension");
        }
        m_versions.push_back(ProtocolVersion(reader.get_uint16_t()));
    } else {
        auto versions = reader.get_range<uint16_t>(1, 1, 127);

        for (auto v : versions) {
            m_versions.push_back(ProtocolVersion(v));
        }

        if (extension_size != 1 + 2 * versions.size()) {
            throw std::runtime_error("Client sent invalid supported_versions extension");
        }
    }
}

bool Supported_Versions::supports(ProtocolVersion version) const {
    for (auto v : m_versions) {
        if (version == v) {
            return true;
        }
    }
    return false;
}

#define MAX_PLAINTEXT_SIZE (16 * 1024)

Record_Size_Limit::Record_Size_Limit(const uint16_t limit)
    : m_limit(limit) {
    utils::ThrowIfFalse(limit >= 64, "RFC 8449 does not allow record size limits smaller than 64 bytes");
    utils::ThrowIfFalse(
        limit <= MAX_PLAINTEXT_SIZE + 1 /* encrypted content type byte */,
        "RFC 8449 does not allow record size limits larger than 2^14+1");
}

Record_Size_Limit::Record_Size_Limit(stream::DataReader& reader, uint16_t extension_size, Side from) {
    if (extension_size != 2) {
        throw std::runtime_error("invalid record_size_limit extension");
    }

    m_limit = reader.get_uint16_t();

    // RFC 8449 4.
    //    This value is the length of the plaintext of a protected record.
    //    The value includes the content type and padding added in TLS 1.3 (that
    //    is, the complete length of TLSInnerPlaintext).
    //
    //    A server MUST NOT enforce this restriction; a client might advertise
    //    a higher limit that is enabled by an extension or version the server
    //    does not understand. A client MAY abort the handshake with an
    //    "illegal_parameter" alert.
    //
    // Note: We are currently supporting this extension in TLS 1.3 only, hence
    //       we check for the TLS 1.3 limit. The TLS 1.2 limit would not include
    //       the "content type byte" and hence be one byte less!
    if (m_limit > MAX_PLAINTEXT_SIZE + 1 /* encrypted content type byte */ && from == Side::Server) {
        throw std::runtime_error("Server requested a record size limit larger than the protocol's maximum");
    }

    // RFC 8449 4.
    //    Endpoints MUST NOT send a "record_size_limit" extension with a value
    //    smaller than 64.  An endpoint MUST treat receipt of a smaller value
    //    as a fatal error and generate an "illegal_parameter" alert.
    if (m_limit < 64) {
        throw std::runtime_error("Received a record size limit smaller than 64 bytes");
    }
}

Renegotiation_Extension::Renegotiation_Extension(stream::DataReader& reader, uint16_t extension_size)
    : m_reneg_data(reader.get_range<uint8_t>(1, 0, 255)) {
    if (m_reneg_data.size() + 1 != extension_size) {
        throw std::runtime_error("Bad encoding for secure renegotiation extn");
    }
}

} // namespace snet::tls