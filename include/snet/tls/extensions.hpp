/// @file
/// @brief Declaration of the TLS extensions.

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
#include <snet/utils/data_reader.hpp>

namespace snet::tls {

/// @brief Enumeration of the TLS extension codes.
enum class ExtensionCode : std::uint16_t {
    ServerNameIndication = 0,                  ///< Server Name Indication (SNI) extension.
    ApplicationLayerProtocolNegotiation = 16,  ///< Application Layer Protocol Negotiation (ALPN) extension.
    ClientCertificateType = 19,                ///< Client Certificate Type extension.
    ServerCertificateType = 20,                ///< Server Certificate Type extension.
    EncryptThenMac = 22,                       ///< Encrypt-then-MAC extension.
    ExtendedMasterSecret = 23,                 ///< Extended Master Secret extension.
    RecordSizeLimit = 28,                      ///< Record Size Limit extension.
    SupportedVersions = 43,                    ///< Supported Versions extension.
    SafeRenegotiation = 65281,                 ///< Safe Renegotiation extension.
};

/// @brief Base class for TLS extensions.
class Extension {
public:
    /// @brief Virtual destructor.
    virtual ~Extension() = default;

    /// @brief Gets the type of the extension.
    /// @return The extension code.
    virtual ExtensionCode type() const = 0;

    /// @brief Checks if the extension should be encoded.
    /// @return True if the extension should be encoded, false otherwise.
    virtual bool empty() const = 0;
};

/// @brief Server Name Indicator extension (RFC 3546).
class ServerNameIndicator final : public Extension {
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for server name indication.
    static ExtensionCode staticType() {
        return ExtensionCode::ServerNameIndication;
    }

    /// @brief Gets the type of the extension.
    /// @return The extension code for server name indication.
    ExtensionCode type() const override {
        return staticType();
    }

    /// @brief Constructor with hostname.
    /// @param hostname The server hostname.
    explicit ServerNameIndicator(std::string_view hostname)
        : hostname_(hostname) {
    }

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    ServerNameIndicator(utils::DataReader& reader, uint16_t extensionSize);

    /// @brief Gets the server hostname.
    /// @return The server hostname.
    std::string host_name() const {
        return hostname_;
    }

    /// @brief Checks if the extension is empty.
    /// @retval false Always returns false as this extension is always sent.
    bool empty() const override {
        return false;
    }

private:
    std::string hostname_;
};

/// @brief ALPN (Application-Layer Protocol Negotiation) extension (RFC 7301).
class ALPN final : public Extension {
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for ALPN.
    static ExtensionCode staticType() {
        return ExtensionCode::ApplicationLayerProtocolNegotiation;
    }

    /// @brief Gets the type of the extension.
    /// @return The extension code for ALPN.
    ExtensionCode type() const override {
        return staticType();
    }

    /// @brief Gets the list of protocols.
    /// @return The list of protocols.
    const std::vector<std::string>& protocols() const {
        return protocols_;
    }

    /// @brief Gets a single protocol.
    /// @return The single protocol.
    std::string singleProtocol() const;

    /// @brief Constructor with a single protocol, used by server.
    /// @param protocol The protocol.
    explicit ALPN(std::string_view protocol)
        : protocols_(1, std::string(protocol)) {
    }

    /// @brief Constructor with a list of protocols, used by client.
    /// @param protocols The list of protocols.
    explicit ALPN(const std::vector<std::string>& protocols)
        : protocols_(protocols) {
    }

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    /// @param from The side (client or server).
    ALPN(utils::DataReader& reader, uint16_t extensionSize, Side from);

    /// @brief Checks if the extension is empty.
    /// @retval true If there are no protocols.
    /// @retval false Otherwise.
    bool empty() const override {
        return protocols_.empty();
    }

private:
    std::vector<std::string> protocols_;
};

/// @brief Certificate types as defined in RFC 8446 4.4.2.
enum class CertificateType : uint8_t {
    X509 = 0,         ///< X.509 certificate.
    RawPublicKey = 2  ///< Raw public key.
};

/// @brief Converts a CertificateType to a string representation.
/// @param type The CertificateType to convert.
/// @return The string representation of the CertificateType.
std::string CertificateTypeToString(CertificateType type);

/// @brief Converts a string representation to a CertificateType.
/// @param type_str The string representation to convert.
/// @return The corresponding CertificateType.
CertificateType CertificateTypeFromString(const std::string& typeStr);

/// @brief Base class for 'ClientCertificateType' and 'ServerCertificateType' extensions (RFC 7250).
class CertificateTypeBase : public Extension {
public:
    /// @brief Constructor called by the client to advertise support for a number of certificate types.
    /// @param supportedCertTypes The supported certificate types.
    CertificateTypeBase(std::vector<CertificateType> supportedCertTypes);

protected:
    /// @brief Constructor called by the server to select a certificate type to be used in the handshake.
    /// @param certificateTypeFromClient The certificate type from the client.
    /// @param serverPreference The server's preferred certificate types.
    CertificateTypeBase(
        const CertificateTypeBase& certificateTypeFromClient,
        const std::vector<CertificateType>& serverPreference);

public:
    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    /// @param from The side (client or server).
    CertificateTypeBase(utils::DataReader& reader, uint16_t extensionSize, Side from);

    /// @brief Validates the selected certificate type from the server.
    /// @param fromServer The certificate type from the server.
    void validateSelection(const CertificateTypeBase& fromServer) const;

    /// @brief Gets the selected certificate type.
    /// @return The selected certificate type.
    CertificateType selectedCertificateType() const;

    /// @brief Checks if the extension should be encoded.
    /// @retval true If the client has no remaining certificate types to send other than the default X.509 type.
    /// @retval false Otherwise.
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

/// @brief Client Certificate Type extension (RFC 7250).
class ClientCertificateType final : public CertificateTypeBase {
public:
    using CertificateTypeBase::CertificateTypeBase;

    /// @brief Creates the Server Hello extension from the received client preferences.
    /// @param cct The client certificate type.
    ClientCertificateType(const ClientCertificateType& cct);

    /// @brief Gets the static type of the extension.
    /// @return The extension code for client certificate type.
    static ExtensionCode staticType() {
        return ExtensionCode::ClientCertificateType;
    }

    /// @brief Gets the type of the extension.
    /// @return The extension code for client certificate type.
    ExtensionCode type() const override {
        return staticType();
    }
};

/// @brief Server Certificate Type extension (RFC 7250).
class ServerCertificateType final : public CertificateTypeBase {
public:
    using CertificateTypeBase::CertificateTypeBase;

    /// @brief Creates the Server Hello extension from the received client preferences.
    /// @param sct The server certificate type.
    ServerCertificateType(const ServerCertificateType& sct);

    /// @brief Gets the static type of the extension.
    /// @return The extension code for server certificate type.
    static ExtensionCode staticType() {
        return ExtensionCode::ServerCertificateType;
    }

    /// @brief Gets the type of the extension.
    /// @return The extension code for server certificate type.
    ExtensionCode type() const override {
        return staticType();
    }
};

/// @brief Extended Master Secret Extension (RFC 7627).
class ExtendedMasterSecret final : public Extension {
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for Extended Master Secret.
    static ExtensionCode staticType() {
        return ExtensionCode::ExtendedMasterSecret;
    }

    /// @brief Gets the type of the extension.
    /// @return The extension code for Extended Master Secret.
    ExtensionCode type() const override {
        return staticType();
    }

    /// @brief Checks if the extension should be encoded.
    /// @retval false Always returns false as this extension is always sent.
    bool empty() const override {
        return false;
    }

    /// @brief Default constructor.
    ExtendedMasterSecret() = default;

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    ExtendedMasterSecret(utils::DataReader& reader, uint16_t extensionSize);
};

/// @brief Encrypt-then-MAC Extension (RFC 7366).
class EncryptThenMAC final : public Extension {
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for Encrypt-then-MAC.
    static ExtensionCode staticType() {
        return ExtensionCode::EncryptThenMac;
    }

    /// @brief Gets the type of the extension.
    /// @return The extension code for Encrypt-then-MAC.
    ExtensionCode type() const override {
        return staticType();
    }

    /// @brief Checks if the extension should be encoded.
    /// @retval false Always returns false as this extension is always sent.
    bool empty() const override {
        return false;
    }

    /// @brief Default constructor.
    EncryptThenMAC() = default;

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    EncryptThenMAC(utils::DataReader& reader, uint16_t extensionSize);
};

/// @brief Supported Versions extension (RFC 8446).
class SupportedVersions final : public Extension {
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for Supported Versions.
    static ExtensionCode staticType() {
        return ExtensionCode::SupportedVersions;
    }

    /// @brief Gets the type of the extension.
    /// @return The extension code for Supported Versions.
    ExtensionCode type() const override {
        return staticType();
    }

    /// @brief Checks if the extension should be encoded.
    /// @retval true If there are no supported versions.
    /// @retval false Otherwise.
    bool empty() const override {
        return versions_.empty();
    }

    /// @brief Constructor with a single protocol version.
    /// @param version The protocol version.
    SupportedVersions(ProtocolVersion version) {
        versions_.push_back(version);
    }

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    /// @param from The side (client or server).
    SupportedVersions(utils::DataReader& reader, uint16_t extensionSize, Side from);

    /// @brief Checks if the extension supports a specific protocol version.
    /// @param version The protocol version to check.
    /// @retval true If the version is supported.
    /// @retval false Otherwise.
    bool supports(ProtocolVersion version) const;

    /// @brief Gets the list of supported protocol versions.
    /// @return The list of supported protocol versions.
    const std::vector<ProtocolVersion>& versions() const {
        return versions_;
    }

private:
    std::vector<ProtocolVersion> versions_;
};

/// @brief Record Size Limit (RFC 8449).
class RecordSizeLimit final : public Extension {
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for Record Size Limit.
    static ExtensionCode staticType() {
        return ExtensionCode::RecordSizeLimit;
    }

    /// @brief Gets the type of the extension.
    /// @return The extension code for Record Size Limit.
    ExtensionCode type() const override {
        return staticType();
    }

    /// @brief Constructor with record size limit.
    /// @param limit The record size limit.
    explicit RecordSizeLimit(uint16_t limit);

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    /// @param from The side (client or server).
    RecordSizeLimit(utils::DataReader& reader, uint16_t extensionSize, Side from);

    /// @brief Gets the record size limit.
    /// @return The record size limit.
    uint16_t limit() const {
        return limit_;
    }

    /// @brief Checks if the extension should be encoded.
    /// @retval true If the limit is 0.
    /// @retval false Otherwise.
    bool empty() const override {
        return limit_ == 0;
    }

private:
    uint16_t limit_;
};

/// @brief Renegotiation Indication Extension (RFC 5746).
class RenegotiationExtension final : public Extension {
public:
    /// @brief Gets the static type of the extension.
    /// @return The extension code for Safe Renegotiation.
    static ExtensionCode staticType() {
        return ExtensionCode::SafeRenegotiation;
    }

    /// @brief Gets the type of the extension.
    /// @return The extension code for Safe Renegotiation.
    ExtensionCode type() const override {
        return staticType();
    }

    /// @brief Default constructor.
    RenegotiationExtension() = default;

    /// @brief Constructor with renegotiation data.
    /// @param bits The renegotiation data.
    explicit RenegotiationExtension(const std::vector<uint8_t>& bits)
        : renegData_(bits) {
    }

    /// @brief Constructor with data reader and extension size.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    RenegotiationExtension(utils::DataReader& reader, uint16_t extensionSize);

    /// @brief Gets the renegotiation information.
    /// @return The renegotiation information.
    const std::vector<uint8_t>& renegotiation_info() const {
        return renegData_;
    }

    /// @brief Checks if the extension should be encoded.
    /// @retval false Always returns false as this extension is always sent.
    bool empty() const override {
        return false;
    }

private:
    std::vector<uint8_t> renegData_;
};

/// @brief Unknown extensions are deserialized as this type.
class UnknownExtension final : public Extension {
public:
    /// @brief Constructor with extension code, data reader, and extension size.
    /// @param type The extension code.
    /// @param reader The data reader.
    /// @param extensionSize The size of the extension.
    UnknownExtension(ExtensionCode type, utils::DataReader& reader, uint16_t extensionSize);

    /// @brief Gets the value of the unknown extension.
    /// @return The value of the unknown extension.
    const std::vector<uint8_t>& value() {
        return value_;
    }

    /// @brief Checks if the extension should be encoded.
    /// @retval false Always returns false as this extension is always sent.
    bool empty() const override {
        return false;
    }

    /// @brief Gets the type of the extension.
    /// @return The extension code.
    ExtensionCode type() const override {
        return type_;
    }

private:
    ExtensionCode type_;
    std::vector<uint8_t> value_;
};

/// @brief Represents a block of extensions in a hello message.
class Extensions final {
public:
    /// @brief Gets the types of extensions.
    /// @return A set of extension codes.
    std::set<ExtensionCode> extensionTypes() const;

    /// @brief Gets all extensions.
    /// @return A vector of unique pointers to extensions.
    const std::vector<std::unique_ptr<Extension>>& all() const {
        return extensions_;
    }

    /// @brief Gets an extension of a specific type.
    /// @tparam T The type of the extension.
    /// @return A pointer to the extension if found, otherwise nullptr.
    template <typename T>
    T* get() const {
        return dynamic_cast<T*>(get(T::staticType()));
    }

    /// @brief Checks if an extension of a specific type exists.
    /// @tparam T The type of the extension.
    /// @return True if the extension exists, false otherwise.
    template <typename T>
    bool has() const {
        return get<T>() != nullptr;
    }

    /// @brief Checks if an extension of a specific type exists.
    /// @param type The extension code.
    /// @return True if the extension exists, false otherwise.
    bool has(ExtensionCode type) const {
        return get(type) != nullptr;
    }

    /// @brief Gets the number of extensions.
    /// @return The number of extensions.
    size_t size() const {
        return extensions_.size();
    }

    /// @brief Checks if there are no extensions.
    /// @return True if there are no extensions, false otherwise.
    bool empty() const {
        return extensions_.empty();
    }

    /// @brief Adds an extension.
    /// @param extn The unique pointer to the extension.
    void add(std::unique_ptr<Extension> extn);

    /// @brief Adds an extension.
    /// @param extn The pointer to the extension.
    void add(Extension* extn) {
        add(std::unique_ptr<Extension>(extn));
    }

    /// @brief Gets an extension of a specific type.
    /// @param type The extension code.
    /// @return A pointer to the extension if found, otherwise nullptr.
    Extension* get(ExtensionCode type) const {
        const auto i = std::find_if(
            extensions_.cbegin(), extensions_.cend(), [type](const auto& ext) { return ext->type() == type; });

        return (i != extensions_.end()) ? i->get() : nullptr;
    }

    /// @brief Deserializes extensions from a data reader.
    /// @param reader The data reader.
    /// @param from The side (client or server).
    /// @param messageType The handshake type.
    void deserialize(utils::DataReader& reader, Side from, HandshakeType messageType);

    /// @brief Checks if the extensions contain any types other than the allowed ones.
    /// @param allowedExtensions The allowed extension types.
    /// @param allowUnknownExtensions If true, ignores unrecognized extensions.
    /// @return True if there are any extensions not in the allowed set, false otherwise.
    bool containsOtherThan(
        const std::set<ExtensionCode>& allowedExtensions, bool allowUnknownExtensions = false) const;

    /// @brief Checks if the extensions contain any implemented types other than the allowed ones.
    /// @param allowedExtensions The allowed extension types.
    /// @return True if there are any implemented extensions not in the allowed set, false otherwise.
    bool containsImplementedExtensionsOtherThan(const std::set<ExtensionCode>& allowedExtensions) const {
        return containsOtherThan(allowedExtensions, true);
    }

    /// @brief Takes an extension of a specific type out of the extensions list.
    /// @tparam T The type of the extension.
    /// @return A unique pointer to the extension if found, otherwise nullptr.
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

    /// @brief Takes an extension of a specific type out of the extensions list.
    /// @param type The extension code.
    /// @return A unique pointer to the extension if found, otherwise nullptr.
    std::unique_ptr<Extension> take(ExtensionCode type);

    /// @brief Removes an extension from the extensions list if it exists.
    /// @param type The extension code.
    /// @return True if the extension existed and was removed, false otherwise.
    bool removeExtension(ExtensionCode type) {
        return take(type) != nullptr;
    }

    /// @brief Default constructor.
    Extensions() = default;

    Extensions(const Extensions&) = delete;
    Extensions& operator=(const Extensions&) = delete;

    /// @brief Move constructor.
    Extensions(Extensions&&) = default;

    /// @brief Move assignment operator.
    Extensions& operator=(Extensions&&) = default;

    /// @brief Constructor with data reader, side, and handshake type.
    /// @param reader The data reader.
    /// @param side The side (client or server).
    /// @param messageType The handshake type.
    Extensions(utils::DataReader& reader, Side side, HandshakeType messageType) {
        deserialize(reader, side, messageType);
    }

private:
    std::vector<std::unique_ptr<Extension>> extensions_;
};

} // namespace snet::tls