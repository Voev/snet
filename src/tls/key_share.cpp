#include <algorithm>
#include <utility>
#include <variant>

#include <snet/crypto/pointers.hpp>
#include <snet/crypto/asymm_key.hpp>

#include <snet/tls/key_share.hpp>
#include <snet/utils/load_store.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>

using namespace casket::utils;

namespace snet::tls
{

class KeyShareEntry
{
public:
    KeyShareEntry(utils::DataReader& reader)
    {
        groupParams_ = static_cast<GroupParams>(reader.get_uint16_t());
        keyExchange_ = reader.get_tls_length_value(2);
    }

    KeyShareEntry(const GroupParams groupParams)
        : groupParams_(groupParams)
    {
    }

    void setPublicKey(const Key* key)
    {
        if (groupParams_.is_pure_ecc_group())
        {
            keyExchange_ = crypto::akey::getEncodedPublicKey(key);
        }
        else
        {
            throw RuntimeError("Unsupported key exchange algorithm");
        }
    }

    crypto::KeyPtr getPublicKey() const
    {
        crypto::KeyPtr publicKey(GenerateGroupParams(groupParams_));
        crypto::akey::setEncodedPublicKey(publicKey, keyExchange_);
        return publicKey;
    }

    bool empty() const
    {
        return (groupParams_ == GroupParams::NONE) && keyExchange_.empty();
    }

    size_t serialize(std::span<uint8_t> buffer) const
    {
        ThrowIfTrue(buffer.size_bytes() < 2, "buffer too small");

        const uint16_t namedCurveID = groupParams_.wire_code();
        buffer[0] = utils::get_byte<0>(namedCurveID);
        buffer[1] = utils::get_byte<1>(namedCurveID);

        auto size = utils::append_tls_length_value(buffer.subspan(2), keyExchange_.data(), keyExchange_.size(), 2);
        size += 2;

        return size;
    }

    GroupParams group() const
    {
        return groupParams_;
    }

private:
    GroupParams groupParams_;
    std::vector<uint8_t> keyExchange_;
};

class KeyShareClientHello;

class KeyShareServerHello
{
public:
    KeyShareServerHello(utils::DataReader& reader, uint16_t)
        : serverKeyShare_(reader)
    {
    }

    KeyShareServerHello(GroupParams group, const Key* serverKey)
        : serverKeyShare_(group)
    {
        serverKeyShare_.setPublicKey(serverKey);
    }

    ~KeyShareServerHello() = default;

    KeyShareServerHello(const KeyShareServerHello&) = delete;
    KeyShareServerHello& operator=(const KeyShareServerHello&) = delete;

    KeyShareServerHello(KeyShareServerHello&&) = default;
    KeyShareServerHello& operator=(KeyShareServerHello&&) = default;

    size_t serialize(std::span<uint8_t> buffer) const
    {
        return serverKeyShare_.serialize(buffer);
    }

    void setPublicKey(const Key* key)
    {
        serverKeyShare_.setPublicKey(key);
    }

    crypto::KeyPtr getPublicKey(size_t)
    {
        return serverKeyShare_.getPublicKey();
    }

    bool empty() const
    {
        return serverKeyShare_.empty();
    }

    KeyShareEntry& get_singleton_entry()
    {
        return serverKeyShare_;
    }

    const KeyShareEntry& get_singleton_entry() const
    {
        return serverKeyShare_;
    }

    std::vector<GroupParams> offered_groups() const
    {
        return {selected_group()};
    }

    GroupParams selected_group() const
    {
        return serverKeyShare_.group();
    }

private:
    KeyShareEntry serverKeyShare_;
};

class KeyShareClientHello
{
public:
    KeyShareClientHello(utils::DataReader& reader, uint16_t /* extension_size */)
    {
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
            ThrowIfFalse(read_so_far <= client_key_share_length, "");
            return client_key_share_length - read_so_far;
        };

        while (reader.has_remaining() && remaining() > 0)
        {
            if (remaining() < 4)
            {
                throw RuntimeError("Not enough data to read another KeyShareEntry");
            }

            KeyShareEntry new_entry(reader);

            // RFC 8446 4.2.8
            //    Clients MUST NOT offer multiple KeyShareEntry values for the same
            //    group. [...]
            //    Servers MAY check for violations of these rules and abort the
            //    handshake with an "illegal_parameter" alert if one is violated.
            if (std::find_if(clientKeyShares_.begin(), clientKeyShares_.end(), [&](const auto& entry)
                             { return entry.group() == new_entry.group(); }) != clientKeyShares_.end())
            {
                throw RuntimeError("Received multiple key share entries for the same group");
            }

            clientKeyShares_.emplace_back(std::move(new_entry));
        }

        if ((reader.read_so_far() - read_bytes_so_far_begin) != client_key_share_length)
        {
            throw RuntimeError("Read bytes are not equal client KeyShare length");
        }
    }

    KeyShareClientHello(const std::vector<GroupParams>& supported)
    {
        for (const auto group : supported)
        {
            clientKeyShares_.emplace_back(group);
        }
    }

    ~KeyShareClientHello() = default;

    KeyShareClientHello(const KeyShareClientHello&) = delete;
    KeyShareClientHello& operator=(const KeyShareClientHello&) = delete;

    KeyShareClientHello(KeyShareClientHello&&) = default;
    KeyShareClientHello& operator=(KeyShareClientHello&&) = default;

    void retry_offer(const GroupParams to_offer)
    {
        clientKeyShares_.clear();
        clientKeyShares_.emplace_back(to_offer);
    }

    std::vector<GroupParams> offered_groups() const
    {
        std::vector<GroupParams> offered_groups;
        offered_groups.reserve(clientKeyShares_.size());
        for (const auto& share : clientKeyShares_)
        {
            offered_groups.push_back(share.group());
        }
        return offered_groups;
    }

    GroupParams selected_group() const
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

    size_t serialize(std::span<uint8_t> buffer) const
    {
        ThrowIfTrue(buffer.size_bytes() < 2, "buffer too small");

        auto data = buffer.subspan(2);
        uint16_t totalBytes = 0;

        for (const auto& share : clientKeyShares_)
        {
            auto shareBytes = share.serialize(data);
            data = data.subspan(shareBytes);
            totalBytes += shareBytes;
        }

        buffer[0] = utils::get_byte<0>(totalBytes);
        buffer[1] = utils::get_byte<1>(totalBytes);
        totalBytes += 2;

        return totalBytes;
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

class KeyShareHelloRetryRequest
{
public:
    KeyShareHelloRetryRequest(utils::DataReader& reader, uint16_t extension_size)
    {
        constexpr auto sizeof_uint16_t = sizeof(uint16_t);

        if (extension_size != sizeof_uint16_t)
        {
            throw RuntimeError("Size of KeyShare extension in HelloRetryRequest must be {} bytes", sizeof_uint16_t);
        }

        selectedGroupParams_ = static_cast<GroupParams>(reader.get_uint16_t());
    }

    KeyShareHelloRetryRequest(GroupParams selected_group)
        : selectedGroupParams_(selected_group)
    {
    }

    ~KeyShareHelloRetryRequest() = default;

    KeyShareHelloRetryRequest(const KeyShareHelloRetryRequest&) = delete;
    KeyShareHelloRetryRequest& operator=(const KeyShareHelloRetryRequest&) = delete;

    KeyShareHelloRetryRequest(KeyShareHelloRetryRequest&&) = default;
    KeyShareHelloRetryRequest& operator=(KeyShareHelloRetryRequest&&) = default;

    size_t serialize(std::span<uint8_t> buffer) const
    {
        auto code = selectedGroupParams_.wire_code();
        buffer[0] = utils::get_byte<0>(code);
        buffer[1] = utils::get_byte<1>(code);
        return 2;
    }

    GroupParams selected_group() const
    {
        return selectedGroupParams_;
    }

    std::vector<GroupParams> offered_groups() const
    {
        throw std::invalid_argument("Hello Retry Request never offers any key exchange groups");
    }

    bool empty() const
    {
        return selectedGroupParams_ == GroupParams::NONE;
    }

private:
    GroupParams selectedGroupParams_;
};

class KeyShare::KeyShareImpl
{
public:
    using KeyShareType = std::variant<KeyShareClientHello, KeyShareServerHello, KeyShareHelloRetryRequest>;

    KeyShareImpl(KeyShareType ks)
        : keyShare(std::move(ks))
    {
    }

    KeyShareType keyShare;
};

KeyShare::KeyShare(utils::DataReader& reader, uint16_t extensionSize, HandshakeType messageType)
{
    if (messageType == HandshakeType::ClientHello)
    {
        impl_ = std::make_unique<KeyShareImpl>(KeyShareClientHello(reader, extensionSize));
    }
    else if (messageType == HandshakeType::HelloRetryRequest)
    {
        impl_ = std::make_unique<KeyShareImpl>(KeyShareHelloRetryRequest(reader, extensionSize));
    }
    else if (messageType == HandshakeType::ServerHello)
    {
        impl_ = std::make_unique<KeyShareImpl>(KeyShareServerHello(reader, extensionSize));
    }
    else
    {
        throw RuntimeError("cannot create a KeyShare extension for message of type: {}", toString(messageType));
    }
}

size_t KeyShare::serialize(Side whoami, std::span<uint8_t> buffer) const
{
    (void)whoami;
    return std::visit([buffer](const auto& keyshare) { return keyshare.serialize(buffer); }, impl_->keyShare);
}

// ClientHello
KeyShare::KeyShare(const std::vector<GroupParams>& supported)
    : impl_(std::make_unique<KeyShareImpl>(KeyShareClientHello(supported)))
{
}

// HelloRetryRequest
KeyShare::KeyShare(GroupParams selected_group)
    : impl_(std::make_unique<KeyShareImpl>(KeyShareHelloRetryRequest(selected_group)))
{
}

// ServerHello
KeyShare::KeyShare(GroupParams selected_group, const Key* serverKey)
    : impl_(std::make_unique<KeyShareImpl>(KeyShareServerHello(selected_group, serverKey)))
{
}

KeyShare::~KeyShare() noexcept
{
}

bool KeyShare::empty() const
{
    return std::visit([](const auto& key_share) { return key_share.empty(); }, impl_->keyShare);
}

std::vector<GroupParams> KeyShare::offered_groups() const
{
    return std::visit([](const auto& keyshare) { return keyshare.offered_groups(); }, impl_->keyShare);
}

GroupParams KeyShare::selected_group() const
{
    return std::visit([](const auto& keyshare) { return keyshare.selected_group(); }, impl_->keyShare);
}

void KeyShare::setPublicKey(const Key* key)
{
    return std::visit(
        [&](auto&& arg)
        {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, KeyShareServerHello>)
            {
                arg.setPublicKey(key);
            }
            else
            {
                throw std::logic_error("unsupported operation");
            }
        },
        impl_->keyShare);
}

void KeyShare::setPublicKey(const size_t idx, const Key* key)
{
    return std::visit(
        [&](auto&& arg)
        {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, KeyShareClientHello>)
            {
                arg.setPublicKey(idx, key);
            }
            else
            {
                throw std::logic_error("unsupported operation");
            }
        },
        impl_->keyShare);
}

crypto::KeyPtr KeyShare::getPublicKey(size_t i)
{
    return std::visit(
        [&](auto&& arg) -> crypto::KeyPtr
        {
            using T = std::decay_t<decltype(arg)>;
            if constexpr (std::is_same_v<T, KeyShareClientHello>)
            {
                return arg.getPublicKey(i);
            }
            else if constexpr (std::is_same_v<T, KeyShareServerHello>)
            {
                return arg.getPublicKey(i);
            }
            else
            {
                throw std::logic_error("unsupported operation");
            }
            return nullptr;
        },
        impl_->keyShare);
}

void KeyShare::retry_offer(const KeyShare& retry_request_keyshare, const std::vector<GroupParams>& supported_groups)
{
    std::visit(
        [&](auto&& arg1, auto&& arg2)
        {
            using T1 = std::decay_t<decltype(arg1)>;
            using T2 = std::decay_t<decltype(arg2)>;

            if constexpr (std::is_same_v<T1, KeyShareClientHello> && std::is_same_v<T2, KeyShareHelloRetryRequest>)
            {
                auto selected = arg2.selected_group();
                // RFC 8446 4.2.8
                //    [T]he selected_group field [MUST correspond] to a group which was provided in
                //    the "supported_groups" extension in the original ClientHello
                if (std::find(supported_groups.begin(), supported_groups.end(), selected) != supported_groups.end())
                {
                    throw RuntimeError("group was not advertised as supported");
                }

                return arg1.retry_offer(selected);
            }
            else
            {
                throw RuntimeError("can only retry with HelloRetryRequest on a ClientHello KeyShare");
            }
        },
        impl_->keyShare, retry_request_keyshare.impl_->keyShare);
}

} // namespace snet::tls
