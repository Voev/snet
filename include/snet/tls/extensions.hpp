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

enum class ExtensionCode : std::uint16_t {
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
    virtual ExtensionCode type() const = 0;

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
    static ExtensionCode staticType() {
        return ExtensionCode::ServerNameIndication;
    }

    ExtensionCode type() const override {
        return staticType();
    }

    explicit ServerNameIndicator(std::string_view hostname)
        : hostname_(hostname) {
    }

    ServerNameIndicator(stream::DataReader& reader, uint16_t extension_size);

    std::string host_name() const {
        return hostname_;
    }

    bool empty() const override {
        return false;
    }

private:
    std::string hostname_;
};

/**
 * ALPN (RFC 7301)
 */
class ALPN final : public Extension {
public:
    static ExtensionCode staticType() {
        return ExtensionCode::ApplicationLayerProtocolNegotiation;
    }

    ExtensionCode type() const override {
        return staticType();
    }

    const std::vector<std::string>& protocols() const {
        return protocols_;
    }

    std::string single_protocol() const;

    /**
     * Single protocol, used by server
     */
    explicit ALPN(std::string_view protocol)
        : protocols_(1, std::string(protocol)) {
    }

    /**
     * List of protocols, used by client
     */
    explicit ALPN(const std::vector<std::string>& protocols)
        : protocols_(protocols) {
    }

    ALPN(stream::DataReader& reader, uint16_t extension_size, Side from);

    bool empty() const override {
        return protocols_.empty();
    }

private:
    std::vector<std::string> protocols_;
};

// As defined in RFC 8446 4.4.2
enum class CertificateType : uint8_t { X509 = 0, RawPublicKey = 2 };

std::string CertificateType_to_string(CertificateType type);
CertificateType CertificateType_from_string(const std::string& type_str);

/**
 * RFC 7250
 * Base class for 'client_CertificateType' and 'server_CertificateType' extensions.
 */
class CertificateTypeBase : public Extension {
public:
    /**
     * Called by the client to advertise support for a number of cert types.
     */
    CertificateTypeBase(std::vector<CertificateType> supported_cert_types);

protected:
    /**
     * Called by the server to select a cert type to be used in the handshake.
     */
    CertificateTypeBase(
        const CertificateTypeBase& CertificateType_from_client,
        const std::vector<CertificateType>& server_preference);

public:
    CertificateTypeBase(stream::DataReader& reader, uint16_t extension_size, Side from);

    void validate_selection(const CertificateTypeBase& from_server) const;
    CertificateType selected_CertificateType() const;

    bool empty() const override {
        // RFC 7250 4.1
        //    If the client has no remaining certificate types to send in the
        //    client hello, other than the default X.509 type, it MUST omit the
        //    entire client[/server]_CertificateType extension [...].
        return from_ == Side::Client && certTypes_.size() == 1 &&
               certTypes_.front() == CertificateType::X509;
    }

private:
    std::vector<CertificateType> certTypes_;
    Side from_;
};

class ClientCertificateType final : public CertificateTypeBase {
public:
    using CertificateTypeBase::CertificateTypeBase;

    /**
     * Creates the Server Hello extension from the received client preferences.
     */
    ClientCertificateType(const ClientCertificateType& cct);

    static ExtensionCode staticType() {
        return ExtensionCode::ClientCertificateType;
    }

    ExtensionCode type() const override {
        return staticType();
    }
};

class ServerCertificateType final : public CertificateTypeBase {
public:
    using CertificateTypeBase::CertificateTypeBase;

    /**
     * Creates the Server Hello extension from the received client preferences.
     */
    ServerCertificateType(const ServerCertificateType& sct);

    static ExtensionCode staticType() {
        return ExtensionCode::ServerCertificateType;
    }

    ExtensionCode type() const override {
        return staticType();
    }
};

/**
 * Extended Master Secret Extension (RFC 7627)
 */
class ExtendedMasterSecret final : public Extension {
public:
    static ExtensionCode staticType() {
        return ExtensionCode::ExtendedMasterSecret;
    }

    ExtensionCode type() const override {
        return staticType();
    }

    bool empty() const override {
        return false;
    }

    ExtendedMasterSecret() = default;

    ExtendedMasterSecret(stream::DataReader& reader, uint16_t extension_size);
};

/**
 * Encrypt-then-MAC Extension (RFC 7366)
 */
class EncryptThenMAC final : public Extension {
public:
    static ExtensionCode staticType() {
        return ExtensionCode::EncryptThenMac;
    }

    ExtensionCode type() const override {
        return staticType();
    }

    bool empty() const override {
        return false;
    }

    EncryptThenMAC() = default;

    EncryptThenMAC(stream::DataReader& reader, uint16_t extension_size);
};

/**
 * Supported Versions from RFC 8446
 */
class SupportedVersions final : public Extension {
public:
    static ExtensionCode staticType() {
        return ExtensionCode::SupportedVersions;
    }

    ExtensionCode type() const override {
        return staticType();
    }

    bool empty() const override {
        return versions_.empty();
    }

    SupportedVersions(ProtocolVersion version) {
        versions_.push_back(version);
    }

    SupportedVersions(stream::DataReader& reader, uint16_t extension_size, Side from);

    bool supports(ProtocolVersion version) const;

    const std::vector<ProtocolVersion>& versions() const {
        return versions_;
    }

private:
    std::vector<ProtocolVersion> versions_;
};

/**
 * Record Size Limit (RFC 8449)
 */
class RecordSizeLimit final : public Extension {
public:
    static ExtensionCode staticType() {
        return ExtensionCode::RecordSizeLimit;
    }

    ExtensionCode type() const override {
        return staticType();
    }

    explicit RecordSizeLimit(uint16_t limit);

    RecordSizeLimit(stream::DataReader& reader, uint16_t extension_size, Side from);

    uint16_t limit() const {
        return limit_;
    }

    bool empty() const override {
        return limit_ == 0;
    }

private:
    uint16_t limit_;
};

/**
 * Renegotiation Indication Extension (RFC 5746)
 */
class RenegotiationExtension final : public Extension {
public:
    static ExtensionCode staticType() {
        return ExtensionCode::SafeRenegotiation;
    }

    ExtensionCode type() const override {
        return staticType();
    }

    RenegotiationExtension() = default;

    explicit RenegotiationExtension(const std::vector<uint8_t>& bits)
        : renegData_(bits) {
    }

    RenegotiationExtension(stream::DataReader& reader, uint16_t extension_size);

    const std::vector<uint8_t>& renegotiation_info() const {
        return renegData_;
    }

    bool empty() const override {
        return false;
    } // always send this

private:
    std::vector<uint8_t> renegData_;
};

/**
 * Unknown extensions are deserialized as this type
 */
class UnknownExtension final : public Extension {
public:
    UnknownExtension(ExtensionCode type, stream::DataReader& reader, uint16_t extension_size);

    const std::vector<uint8_t>& value() {
        return value_;
    }

    bool empty() const override {
        return false;
    }

    ExtensionCode type() const override {
        return type_;
    }

private:
    ExtensionCode type_;
    std::vector<uint8_t> value_;
};

/**
 * Represents a block of extensions in a hello message
 */
class Extensions final {
public:
    std::set<ExtensionCode> extension_types() const;

    const std::vector<std::unique_ptr<Extension>>& all() const {
        return extensions_;
    }

    template <typename T>
    T* get() const {
        return dynamic_cast<T*>(get(T::staticType()));
    }

    template <typename T>
    bool has() const {
        return get<T>() != nullptr;
    }

    bool has(ExtensionCode type) const {
        return get(type) != nullptr;
    }

    size_t size() const {
        return extensions_.size();
    }

    bool empty() const {
        return extensions_.empty();
    }

    void add(std::unique_ptr<Extension> extn);

    void add(Extension* extn) {
        add(std::unique_ptr<Extension>(extn));
    }

    Extension* get(ExtensionCode type) const {
        const auto i = std::find_if(
            extensions_.cbegin(), extensions_.cend(), [type](const auto& ext) { return ext->type() == type; });

        return (i != extensions_.end()) ? i->get() : nullptr;
    }

    void deserialize(stream::DataReader& reader, Side from, HandshakeType message_type);

    /**
     * @param allowed_extensions        extension types that are allowed
     * @param allow_unknown_extensions  if true, ignores unrecognized extensions
     * @returns true if this contains any extensions that are not contained in @p allowed_extensions.
     */
    bool contains_other_than(
        const std::set<ExtensionCode>& allowed_extensions, bool allow_unknown_extensions = false) const;

    /**
     * @param allowed_extensions  extension types that are allowed
     * @returns true if this contains any extensions that
     *          are not contained in @p allowed_extensions.
     */
    bool contains_implemented_extensions_other_than(const std::set<ExtensionCode>& allowed_extensions) const {
        return contains_other_than(allowed_extensions, true);
    }

    /**
     * Take the extension with the given type out of the extensions list.
     * Returns a nullptr if the extension didn't exist.
     */
    template <typename T>
    decltype(auto) take() {
        std::unique_ptr<T> out_ptr;

        auto ext = take(T::staticType());
        if (ext != nullptr) {
            out_ptr.reset(dynamic_cast<T*>(ext.get()));
            ext.release();
        }

        return out_ptr;
    }

    /**
     * Take the extension with the given type out of the extensions list.
     * Returns a nullptr if the extension didn't exist.
     */
    std::unique_ptr<Extension> take(ExtensionCode type);

    /**
     * Remove an extension from this extensions object, if it exists.
     * Returns true if the extension existed (and thus is now removed),
     * otherwise false (the extension wasn't set in the first place).
     *
     * Note: not used internally, might be used in Callbacks::tls_modify_extensions()
     */
    bool remove_extension(ExtensionCode type) {
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
    std::vector<std::unique_ptr<Extension>> extensions_;
};

} // namespace snet::tls