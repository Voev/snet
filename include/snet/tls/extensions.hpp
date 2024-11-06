#pragma once

#include <algorithm>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <variant>
#include <vector>
#include <snet/tls/types.hpp>
#include <snet/tls/version.hpp>
#include <snet/stream/data_reader.hpp>

namespace snet::tls {

enum class Extension_Code : uint16_t {
    ServerNameIndication = 0,
    ApplicationLayerProtocolNegotiation = 16,
    ClientCertificateType = 19,
    ServerCertificateType = 20,
    EncryptThenMac = 22,
    ExtendedMasterSecret = 23,
    RecordSizeLimit = 28,
    SupportedVersions = 43,
    SafeRenegotiation = 65281,
};

class Extension {
public:
    virtual ~Extension() = default;

    /**
     * @return code number of the extension
     */
    virtual Extension_Code type() const = 0;

    /**
     * @return if we should encode this extension or not
     */
    virtual bool empty() const = 0;

};

/**
 * Server Name Indicator extension (RFC 3546)
 */
class ServerNameIndicator final : public Extension {
public:
    static Extension_Code static_type() {
        return Extension_Code::ServerNameIndication;
    }

    Extension_Code type() const override {
        return static_type();
    }

    explicit ServerNameIndicator(std::string_view host_name)
        : m_sni_host_name(host_name) {
    }

    ServerNameIndicator(stream::DataReader& reader, uint16_t extension_size);

    std::string host_name() const {
        return m_sni_host_name;
    }

    bool empty() const override {
        return false;
    }

private:
    std::string m_sni_host_name;
};

/**
 * ALPN (RFC 7301)
 */
class Application_Layer_Protocol_Notification final : public Extension {
public:
    static Extension_Code static_type() {
        return Extension_Code::ApplicationLayerProtocolNegotiation;
    }

    Extension_Code type() const override {
        return static_type();
    }

    const std::vector<std::string>& protocols() const {
        return m_protocols;
    }

    std::string single_protocol() const;

    /**
     * Single protocol, used by server
     */
    explicit Application_Layer_Protocol_Notification(std::string_view protocol)
        : m_protocols(1, std::string(protocol)) {
    }

    /**
     * List of protocols, used by client
     */
    explicit Application_Layer_Protocol_Notification(const std::vector<std::string>& protocols)
        : m_protocols(protocols) {
    }

    Application_Layer_Protocol_Notification(stream::DataReader& reader, uint16_t extension_size, Side from);

    bool empty() const override {
        return m_protocols.empty();
    }

private:
    std::vector<std::string> m_protocols;
};

// As defined in RFC 8446 4.4.2
enum class Certificate_Type : uint8_t { X509 = 0, RawPublicKey = 2 };

std::string certificate_type_to_string(Certificate_Type type);
Certificate_Type certificate_type_from_string(const std::string& type_str);

/**
 * RFC 7250
 * Base class for 'client_certificate_type' and 'server_certificate_type' extensions.
 */
class Certificate_Type_Base : public Extension {
public:
    /**
     * Called by the client to advertise support for a number of cert types.
     */
    Certificate_Type_Base(std::vector<Certificate_Type> supported_cert_types);

protected:
    /**
     * Called by the server to select a cert type to be used in the handshake.
     */
    Certificate_Type_Base(
        const Certificate_Type_Base& certificate_type_from_client,
        const std::vector<Certificate_Type>& server_preference);

public:
    Certificate_Type_Base(stream::DataReader& reader, uint16_t extension_size, Side from);

    void validate_selection(const Certificate_Type_Base& from_server) const;
    Certificate_Type selected_certificate_type() const;

    bool empty() const override {
        // RFC 7250 4.1
        //    If the client has no remaining certificate types to send in the
        //    client hello, other than the default X.509 type, it MUST omit the
        //    entire client[/server]_certificate_type extension [...].
        return m_from == Side::Client && m_certificate_types.size() == 1 &&
               m_certificate_types.front() == Certificate_Type::X509;
    }

private:
    std::vector<Certificate_Type> m_certificate_types;
    Side m_from;
};

class Client_Certificate_Type final : public Certificate_Type_Base {
public:
    using Certificate_Type_Base::Certificate_Type_Base;

    /**
     * Creates the Server Hello extension from the received client preferences.
     */
    Client_Certificate_Type(const Client_Certificate_Type& cct);

    static Extension_Code static_type() {
        return Extension_Code::ClientCertificateType;
    }

    Extension_Code type() const override {
        return static_type();
    }
};

class Server_Certificate_Type final : public Certificate_Type_Base {
public:
    using Certificate_Type_Base::Certificate_Type_Base;

    /**
     * Creates the Server Hello extension from the received client preferences.
     */
    Server_Certificate_Type(const Server_Certificate_Type& sct);

    static Extension_Code static_type() {
        return Extension_Code::ServerCertificateType;
    }

    Extension_Code type() const override {
        return static_type();
    }
};

/**
 * Extended Master Secret Extension (RFC 7627)
 */
class Extended_Master_Secret final : public Extension {
public:
    static Extension_Code static_type() {
        return Extension_Code::ExtendedMasterSecret;
    }

    Extension_Code type() const override {
        return static_type();
    }

    bool empty() const override {
        return false;
    }

    Extended_Master_Secret() = default;

    Extended_Master_Secret(stream::DataReader& reader, uint16_t extension_size);
};

/**
 * Encrypt-then-MAC Extension (RFC 7366)
 */
class Encrypt_then_MAC final : public Extension {
public:
    static Extension_Code static_type() {
        return Extension_Code::EncryptThenMac;
    }

    Extension_Code type() const override {
        return static_type();
    }

    bool empty() const override {
        return false;
    }

    Encrypt_then_MAC() = default;

    Encrypt_then_MAC(stream::DataReader& reader, uint16_t extension_size);
};

/**
 * Supported Versions from RFC 8446
 */
class Supported_Versions final : public Extension {
public:
    static Extension_Code static_type() {
        return Extension_Code::SupportedVersions;
    }

    Extension_Code type() const override {
        return static_type();
    }

    bool empty() const override {
        return m_versions.empty();
    }

    Supported_Versions(ProtocolVersion version) {
        m_versions.push_back(version);
    }

    Supported_Versions(stream::DataReader& reader, uint16_t extension_size, Side from);

    bool supports(ProtocolVersion version) const;

    const std::vector<ProtocolVersion>& versions() const {
        return m_versions;
    }

private:
    std::vector<ProtocolVersion> m_versions;
};

/**
 * Record Size Limit (RFC 8449)
 *
 * TODO: the record size limit is currently not honored by the TLS 1.2 stack
 */
class Record_Size_Limit final : public Extension {
public:
    static Extension_Code static_type() {
        return Extension_Code::RecordSizeLimit;
    }

    Extension_Code type() const override {
        return static_type();
    }

    explicit Record_Size_Limit(uint16_t limit);

    Record_Size_Limit(stream::DataReader& reader, uint16_t extension_size, Side from);

    uint16_t limit() const {
        return m_limit;
    }

    bool empty() const override {
        return m_limit == 0;
    }

private:
    uint16_t m_limit;
};

/**
 * Renegotiation Indication Extension (RFC 5746)
 */
class Renegotiation_Extension final : public Extension {
public:
    static Extension_Code static_type() {
        return Extension_Code::SafeRenegotiation;
    }

    Extension_Code type() const override {
        return static_type();
    }

    Renegotiation_Extension() = default;

    explicit Renegotiation_Extension(const std::vector<uint8_t>& bits)
        : m_reneg_data(bits) {
    }

    Renegotiation_Extension(stream::DataReader& reader, uint16_t extension_size);

    const std::vector<uint8_t>& renegotiation_info() const {
        return m_reneg_data;
    }

    bool empty() const override {
        return false;
    } // always send this

private:
    std::vector<uint8_t> m_reneg_data;
};


/**
 * Unknown extensions are deserialized as this type
 */
class Unknown_Extension final : public Extension {
public:
    Unknown_Extension(Extension_Code type, stream::DataReader& reader, uint16_t extension_size);

    const std::vector<uint8_t>& value() {
        return m_value;
    }

    bool empty() const override {
        return false;
    }

    Extension_Code type() const override {
        return m_type;
    }

private:
    Extension_Code m_type;
    std::vector<uint8_t> m_value;
};

/**
 * Represents a block of extensions in a hello message
 */
class Extensions final {
public:
    std::set<Extension_Code> extension_types() const;

    const std::vector<std::unique_ptr<Extension>>& all() const {
        return m_extensions;
    }

    template <typename T>
    T* get() const {
        return dynamic_cast<T*>(get(T::static_type()));
    }

    template <typename T>
    bool has() const {
        return get<T>() != nullptr;
    }

    bool has(Extension_Code type) const {
        return get(type) != nullptr;
    }

    size_t size() const {
        return m_extensions.size();
    }

    bool empty() const {
        return m_extensions.empty();
    }

    void add(std::unique_ptr<Extension> extn);

    void add(Extension* extn) {
        add(std::unique_ptr<Extension>(extn));
    }

    Extension* get(Extension_Code type) const {
        const auto i = std::find_if(
            m_extensions.cbegin(), m_extensions.cend(), [type](const auto& ext) { return ext->type() == type; });

        return (i != m_extensions.end()) ? i->get() : nullptr;
    }

    void deserialize(stream::DataReader& reader, Side from, HandshakeType message_type);

    /**
     * @param allowed_extensions        extension types that are allowed
     * @param allow_unknown_extensions  if true, ignores unrecognized extensions
     * @returns true if this contains any extensions that are not contained in @p allowed_extensions.
     */
    bool contains_other_than(
        const std::set<Extension_Code>& allowed_extensions, bool allow_unknown_extensions = false) const;

    /**
     * @param allowed_extensions  extension types that are allowed
     * @returns true if this contains any extensions implemented by Botan that
     *          are not contained in @p allowed_extensions.
     */
    bool contains_implemented_extensions_other_than(const std::set<Extension_Code>& allowed_extensions) const {
        return contains_other_than(allowed_extensions, true);
    }

    /**
     * Take the extension with the given type out of the extensions list.
     * Returns a nullptr if the extension didn't exist.
     */
    template <typename T>
    decltype(auto) take() {
        std::unique_ptr<T> out_ptr;

        auto ext = take(T::static_type());
        if (ext != nullptr) {
            out_ptr.reset(dynamic_cast<T*>(ext.get()));
            //BOTAN_ASSERT_NOMSG(out_ptr != nullptr);
            ext.release();
        }

        return out_ptr;
    }

    /**
     * Take the extension with the given type out of the extensions list.
     * Returns a nullptr if the extension didn't exist.
     */
    std::unique_ptr<Extension> take(Extension_Code type);

    /**
     * Remove an extension from this extensions object, if it exists.
     * Returns true if the extension existed (and thus is now removed),
     * otherwise false (the extension wasn't set in the first place).
     *
     * Note: not used internally, might be used in Callbacks::tls_modify_extensions()
     */
    bool remove_extension(Extension_Code type) {
        return take(type) != nullptr;
    }

    Extensions() = default;
    Extensions(const Extensions&) = delete;
    Extensions& operator=(const Extensions&) = delete;
    Extensions(Extensions&&) = default;
    Extensions& operator=(Extensions&&) = default;

    Extensions(stream::DataReader& reader, Side side, HandshakeType message_type) {
        deserialize(reader, side, message_type);
    }

private:
    std::vector<std::unique_ptr<Extension>> m_extensions;
};

} // namespace snet::tls