#pragma once
#include <vector>
#include <snet/tls/extensions.hpp>
#include <snet/crypto/group_params.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

class KeyShareEntry final
{
public:
    KeyShareEntry() = default;

    ~KeyShareEntry() = default;

    explicit KeyShareEntry(const crypto::GroupParams groupParams);

    void setGroup(const crypto::GroupParams groupParams) noexcept;

    crypto::GroupParams getGroup() const noexcept;

    void setPublicKey(const Key* key);

    crypto::KeyPtr getPublicKey() const;

    bool empty() const noexcept;

    void deserialize(utils::DataReader& reader);

    size_t serialize(nonstd::span<uint8_t> output) const;

private:
    std::vector<uint8_t> keyExchange_;
    crypto::GroupParams groupParams_;
};

class KeyShareClientHello final
{
public:
    KeyShareClientHello() = default;
    ~KeyShareClientHello() = default;

    KeyShareClientHello(const KeyShareClientHello&) = delete;
    KeyShareClientHello& operator=(const KeyShareClientHello&) = delete;

    KeyShareClientHello(KeyShareClientHello&&) = default;
    KeyShareClientHello& operator=(KeyShareClientHello&&) = default;

    KeyShareClientHello(nonstd::span<const uint8_t> input);

    KeyShareClientHello(const std::vector<crypto::GroupParams>& supported);

    void retryOffer(const crypto::GroupParams toOffer);

    std::vector<crypto::GroupParams> offeredGroups() const;

    crypto::GroupParams selectedGroup() const;

    void setPublicKey(const size_t idx, const Key* key);

    crypto::KeyPtr getPublicKey(const size_t idx);

    bool empty() const;

    void deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output) const;

private:
    std::vector<KeyShareEntry> clientKeyShares_;
};

class KeyShareServerHello final
{
public:
    KeyShareServerHello() = default;
    ~KeyShareServerHello() = default;

    KeyShareServerHello(const KeyShareServerHello&) = delete;
    KeyShareServerHello& operator=(const KeyShareServerHello&) = delete;

    KeyShareServerHello(KeyShareServerHello&&) = default;
    KeyShareServerHello& operator=(KeyShareServerHello&&) = default;

    KeyShareServerHello(crypto::GroupParams group, const Key* serverKey);

    void setPublicKey(const Key* key);

    crypto::KeyPtr getPublicKey(size_t);

    std::vector<crypto::GroupParams> offeredGroups() const;

    crypto::GroupParams selectedGroup() const;

    bool empty() const;

    void deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output) const;

private:
    KeyShareEntry serverKeyShare_;
};

class KeyShareHelloRetryRequest final
{
public:
    KeyShareHelloRetryRequest() = default;
    ~KeyShareHelloRetryRequest() = default;

    KeyShareHelloRetryRequest(const KeyShareHelloRetryRequest&) = delete;
    KeyShareHelloRetryRequest& operator=(const KeyShareHelloRetryRequest&) = delete;

    KeyShareHelloRetryRequest(KeyShareHelloRetryRequest&&) = default;
    KeyShareHelloRetryRequest& operator=(KeyShareHelloRetryRequest&&) = default;

    KeyShareHelloRetryRequest(crypto::GroupParams selectedGroup);

    crypto::GroupParams selectedGroup() const;

    std::vector<crypto::GroupParams> offeredGroups() const;

    bool empty() const;

    void deserialize(nonstd::span<const uint8_t> input);

    size_t serialize(nonstd::span<uint8_t> output) const;

private:
    crypto::GroupParams selectedGroup_;
};

class KeyShare final : public Extension
{
public:
    static ExtensionCode staticType()
    {
        return ExtensionCode::KeyShare;
    }

    ExtensionCode type() const override
    {
        return staticType();
    }

    KeyShare(nonstd::span<const uint8_t> input, HandshakeType messageType);

    KeyShare(const std::vector<crypto::GroupParams>& supported);

    KeyShare(crypto::GroupParams selectedGroup, const Key* serverKey);

    KeyShare(crypto::GroupParams selectedGroup);

    ~KeyShare() noexcept;

    size_t serialize(Side whoami, nonstd::span<uint8_t> output) const override;

    bool empty() const override;

    void setPublicKey(const size_t idx, const Key* key);

    void setPublicKey(const Key* key);

    crypto::KeyPtr getPublicKey(size_t i = 0);

    void retryOffer(const KeyShare& retryRequestKeyShare, const std::vector<crypto::GroupParams>& supportedGroups);

    std::vector<crypto::GroupParams> offeredGroups() const;

    crypto::GroupParams selectedGroup() const;

private:
    using Type = std::variant<KeyShareClientHello, KeyShareServerHello, KeyShareHelloRetryRequest>;
    Type keyShare_;
};

} // namespace snet::tls