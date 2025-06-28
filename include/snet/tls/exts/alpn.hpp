#pragma once
#include <vector>
#include <snet/tls/exts/extension.hpp>

namespace snet::tls
{

/// @brief ALPN (Application-Layer Protocol Negotiation) extension (RFC 7301).
class ALPN final : public Extension
{
public:
    /// @brief Gets the static type of the extension.
    ///
    /// @return Extension code for ALPN.
    static ExtensionCode staticType();

    /// @brief Gets the type of the extension.
    ///
    /// @return Extension code for ALPN.
    ExtensionCode type() const override;

    /// @brief Checks if the extension should be encoded.
    ///
    /// @retval true Should be encoded.
    /// @retval false Otherwise.
    bool empty() const override;

    /// @brief Serialize extension to bytes.
    ///
    /// @param[in] side Side (Client or Server).
    /// @param[in] output Buffer for encoding.
    ///
    /// @return Serialized bytes count.
    size_t serialize(Side side, cpp::span<uint8_t> output) const override;

    /// @brief Constructor with a single protocol, used by server.
    ///
    /// @param[in] protocol Protocol name.
    explicit ALPN(std::string_view protocol);

    /// @brief Constructor with a list of protocols, used by client.
    ///
    /// @param[in] protocols List of protocol names.
    ///
    explicit ALPN(const std::vector<std::string>& protocols);

    /// @brief Constructor with input byte buffer.
    ///
    /// @param[in] side Side (client or server).
    /// @param[in] input Input byte buffer.
    ///
    ALPN(Side side, cpp::span<const uint8_t> input);

    /// @brief Gets the list of protocol names.
    ///
    /// @return List of protocol names.
    const std::vector<std::string>& protocols() const;

    /// @brief Gets a single protocol.
    ///
    /// @return Single protocol name.
    std::string singleProtocol() const;

private:
    std::vector<std::string> protocols_;
};

} // namespace snet::tls