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

    explicit KeyShareEntry(const crypto::GroupParams groupParams)
        : groupParams_(groupParams)
    {
    }

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

    KeyShareClientHello(nonstd::span<const uint8_t> input)
    {
        deserialize(input);
    }

    void deserialize(nonstd::span<const uint8_t> input)
    {
        utils::DataReader reader("ClientHello KeyShare", input);
        // This construction is a crutch to make working with the incoming
        // utils::DataReader bearable. Currently, this reader spans the entire
        // Client_Hello message. Hence, if offset or length fields are skewed
        // or maliciously fabricated, it is possible to read further than the
        // bounds of the current extension.
        // Note that this aplies to many locations in the code base.
        //
        // TODO: Overhaul the utils::DataReader to allow for cheap "sub-readers"
        //       that enforce read bounds of sub-structures while parsing.
        const auto client_key_share_length = reader.get_uint16_t();
        const auto read_bytes_so_far_begin = reader.read_so_far();
        auto remaining = [&]
        {
            const auto read_so_far = reader.read_so_far() - read_bytes_so_far_begin;
            casket::ThrowIfFalse(read_so_far <= client_key_share_length, "");
            return client_key_share_length - read_so_far;
        };

        while (reader.has_remaining() && remaining() > 0)
        {
            if (remaining() < 4)
            {
                throw std::runtime_error("Not enough data to read another KeyShareEntry");
            }

            KeyShareEntry new_entry;
            
            new_entry.deserialize(reader);

            // RFC 8446 4.2.8
            //    Clients MUST NOT offer multiple KeyShareEntry values for the same
            //    group. [...]
            //    Servers MAY check for violations of these rules and abort the
            //    handshake with an "illegal_parameter" alert if one is violated.
            if (std::find_if(clientKeyShares_.begin(), clientKeyShares_.end(), [&](const auto& entry)
                             { return entry.getGroup() == new_entry.getGroup(); }) != clientKeyShares_.end())
            {
                throw std::runtime_error("Received multiple key share entries for the same group");
            }

            clientKeyShares_.emplace_back(std::move(new_entry));
        }

        if ((reader.read_so_far() - read_bytes_so_far_begin) != client_key_share_length)
        {
            throw std::runtime_error("Read bytes are not equal client KeyShare length");
        }
    }

    KeyShareClientHello(const std::vector<crypto::GroupParams>& supported)
    {
        for (const auto group : supported)
        {
            clientKeyShares_.emplace_back(group);
        }
    }

    size_t serialize(nonstd::span<uint8_t> output) const
    {
        casket::ThrowIfTrue(output.size_bytes() < 2, "buffer too small");

        auto data = output.subspan(2);
        uint16_t totalBytes = 0;

        for (const auto& share : clientKeyShares_)
        {
            auto shareBytes = share.serialize(data);
            data = data.subspan(shareBytes);
            totalBytes += shareBytes;
        }

        output[0] = casket::get_byte<0>(totalBytes);
        output[1] = casket::get_byte<1>(totalBytes);
        totalBytes += 2;

        return totalBytes;
    }

    void retryOffer(const crypto::GroupParams to_offer)
    {
        clientKeyShares_.clear();
        clientKeyShares_.emplace_back(to_offer);
    }

    std::vector<crypto::GroupParams> offeredGroups() const
    {
        std::vector<crypto::GroupParams> offered_groups;
        offered_groups.reserve(clientKeyShares_.size());
        for (const auto& share : clientKeyShares_)
        {
            offered_groups.push_back(share.getGroup());
        }
        return offered_groups;
    }

    crypto::GroupParams selectedGroup() const
    {
        throw std::invalid_argument("Client Hello Key Share does not select a group");
    }

    void setPublicKey(const size_t idx, const Key* key)
    {
        clientKeyShares_[idx].setPublicKey(key);
    }

    crypto::KeyPtr getPublicKey(const size_t idx)
    {
        return clientKeyShares_[idx].getPublicKey();
    }

    bool empty() const
    {
        // RFC 8446 4.2.8
        //    Clients MAY send an empty client_shares vector in order to request
        //    group selection from the server, at the cost of an additional round
        //    trip [...].
        return false;
    }

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

    KeyShareServerHello(crypto::GroupParams group, const Key* serverKey)
    {
        serverKeyShare_.setGroup(group);
        serverKeyShare_.setPublicKey(serverKey);
    }

    void deserialize(nonstd::span<const uint8_t> input)
    {
        utils::DataReader reader("ServerHello KeyShare", input);
        serverKeyShare_.deserialize(reader);
        reader.assert_done();
    }

    size_t serialize(nonstd::span<uint8_t> output) const
    {
        return serverKeyShare_.serialize(output);
    }

    void setPublicKey(const Key* key)
    {
        serverKeyShare_.setPublicKey(key);
    }

    crypto::KeyPtr getPublicKey(size_t)
    {
        return serverKeyShare_.getPublicKey();
    }

    std::vector<crypto::GroupParams> offeredGroups() const
    {
        return {selectedGroup()};
    }

    crypto::GroupParams selectedGroup() const
    {
        return serverKeyShare_.getGroup();
    }

    bool empty() const
    {
        return serverKeyShare_.empty();
    }

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

    void deserialize(nonstd::span<const uint8_t> input)
    {
        utils::DataReader reader("HRR KeyShare", input);

        constexpr auto size = sizeof(uint16_t);

        if (reader.remaining_bytes() != size)
        {
            throw casket::RuntimeError("Size of KeyShare extension in HelloRetryRequest must be {} bytes", size);
        }

        selectedGroup_ = static_cast<crypto::GroupParams>(reader.get_uint16_t());
        reader.assert_done();
    }

    KeyShareHelloRetryRequest(crypto::GroupParams selectedGroup)
        : selectedGroup_(selectedGroup)
    {
    }

    size_t serialize(nonstd::span<uint8_t> output) const
    {
        auto code = selectedGroup_.wireCode();
        output[0] = casket::get_byte<0>(code);
        output[1] = casket::get_byte<1>(code);
        return 2;
    }

    crypto::GroupParams selectedGroup() const
    {
        return selectedGroup_;
    }

    std::vector<crypto::GroupParams> offeredGroups() const
    {
        throw std::logic_error("Hello Retry Request never offers any key exchange groups");
    }

    bool empty() const
    {
        return (selectedGroup_ == crypto::GroupParams::NONE);
    }

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