#include <snet/tls/exts/key_share.hpp>

#include <algorithm>
#include <casket/utils/exception.hpp>
#include <snet/crypto/asymm_key.hpp>

namespace snet::tls
{

void KeyShareEntry::setPublicKey(const Key* key)
{
    if (groupParams_.isPureEccGroup())
    {
        keyExchange_ = crypto::AsymmKey::getEncodedPublicKey(key);
    }
    else
    {
        throw casket::RuntimeError("Unsupported key exchange algorithm");
    }
}

crypto::KeyPtr KeyShareEntry::getPublicKey() const
{
    auto pk = crypto::GroupParams::generateParams(groupParams_);
    crypto::AsymmKey::setEncodedPublicKey(pk, keyExchange_);
    return pk;
}

KeyShareClientHello::KeyShareClientHello(const std::vector<crypto::GroupParams>& supported)
{
    clientKeyShares_.reserve(supported.size());
    for (const auto g : supported)
        clientKeyShares_.emplace_back(g);
}

void KeyShareClientHello::retryOffer(crypto::GroupParams toOffer)
{
    clientKeyShares_.clear();
    clientKeyShares_.emplace_back(toOffer);
}

void KeyShareClientHello::offeredGroups(std::vector<crypto::GroupParams>& out) const
{
    out.clear();
    out.reserve(clientKeyShares_.size());
    for (const auto& s : clientKeyShares_)
        out.push_back(s.getGroup());
}

crypto::GroupParams KeyShareClientHello::selectedGroup() const
{
    throw std::invalid_argument("ClientHello KeyShare does not select a group");
}

void KeyShareClientHello::setPublicKey(std::size_t idx, const Key* key)
{
    if (idx >= clientKeyShares_.size())
        throw std::out_of_range("KeyShareClientHello::setPublicKey: index out of range");
    clientKeyShares_[idx].setPublicKey(key);
}

crypto::KeyPtr KeyShareClientHello::getPublicKey(std::size_t idx) const
{
    if (idx >= clientKeyShares_.size())
        throw std::out_of_range("KeyShareClientHello::getPublicKey: index out of range");
    return clientKeyShares_[idx].getPublicKey();
}

utils::DecodeError KeyShareClientHello::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    clientKeyShares_.clear();

    utils::DataReader reader(input);
    const std::uint16_t total = reader.get_uint16_t();
    if (!reader.ok())
    {
        return reader.take_error();
    }

    if (total != reader.remaining_bytes())
    {
        return utils::DecodeError::LengthOutOfRange;
    }

    // Upper bound on entry count: each entry needs >= 4 bytes (group + len).
    try
    {
        clientKeyShares_.reserve(total / 4);
    }
    catch (...)
    {
        return utils::DecodeError::AllocationFailed;
    }

    while (reader.has_remaining())
    {
        KeyShareEntry entry;
        const auto err = entry.deserialize(reader);
        if (err != utils::DecodeError::None)
        {
            clientKeyShares_.clear();
            return err;
        }

        // RFC 8446 §4.2.8: clients MUST NOT offer the same group twice.
        const auto g = entry.getGroup();
        const auto dup = std::find_if(clientKeyShares_.begin(),
                                      clientKeyShares_.end(),
                                      [g](const auto& e)
                                      {
                                          return e.getGroup() == g;
                                      });
        if (dup != clientKeyShares_.end())
        {
            clientKeyShares_.clear();
            return utils::DecodeError::LengthOutOfRange;
        }

        try
        {
            clientKeyShares_.push_back(std::move(entry));
        }
        catch (...)
        {
            clientKeyShares_.clear();
            return utils::DecodeError::AllocationFailed;
        }
    }
    reader.assert_done();
    return reader.take_error();
}

std::size_t KeyShareClientHello::serialize(nonstd::span<uint8_t> output) const noexcept
{
    if (output.size_bytes() < 2)
        return kSerializationFailed;

    std::size_t total = 0;
    auto data = output.subspan(2);
    for (const auto& share : clientKeyShares_)
    {
        const std::size_t n = share.serialize(data);
        if (n == kSerializationFailed)
            return kSerializationFailed;
        data = data.subspan(n);
        total += n;
    }
    if (total > 0xFFFF)
        return kSerializationFailed;

    output[0] = static_cast<std::uint8_t>(total >> 8);
    output[1] = static_cast<std::uint8_t>(total);
    return total + 2;
}

KeyShareServerHello::KeyShareServerHello(crypto::GroupParams group, const Key* serverKey)
{
    serverKeyShare_.setGroup(group);
    serverKeyShare_.setPublicKey(serverKey);
}

void KeyShareServerHello::setPublicKey(const Key* key)
{
    serverKeyShare_.setPublicKey(key);
}

crypto::KeyPtr KeyShareServerHello::getPublicKey(std::size_t) const
{
    return serverKeyShare_.getPublicKey();
}

void KeyShareServerHello::offeredGroups(std::vector<crypto::GroupParams>& out) const
{
    out.clear();
    out.push_back(selectedGroup());
}

utils::DecodeError KeyShareServerHello::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    utils::DataReader reader(input);
    const auto err = serverKeyShare_.deserialize(reader);
    if (err != utils::DecodeError::None)
    {
        return err;
    }
    reader.assert_done();
    return reader.take_error();
}

void KeyShareHelloRetryRequest::offeredGroups(std::vector<crypto::GroupParams>&) const
{
    throw std::logic_error("Hello Retry Request never offers any key exchange groups");
}

utils::DecodeError KeyShareHelloRetryRequest::deserialize(nonstd::span<const uint8_t> input) noexcept
{
    if (input.size() != 2)
    {
        return utils::DecodeError::LengthOutOfRange;
    }

    utils::DataReader reader(input);
    selectedGroup_ = static_cast<crypto::GroupParams>(reader.get_uint16_t());
    return reader.take_error();
}

utils::DecodeError KeyShare::deserialize(Side /*side*/, nonstd::span<const uint8_t> input,
                                         HandshakeType handshakeType) noexcept
{
    switch (handshakeType)
    {
    case HandshakeType::ClientHelloCode:
    {
        KeyShareClientHello inner;
        const auto err = inner.deserialize(input);
        if (err != utils::DecodeError::None)
            return err;
        keyShare_ = std::move(inner);
        return utils::DecodeError::None;
    }
    case HandshakeType::ServerHelloCode:
    {
        KeyShareServerHello inner;
        const auto err = inner.deserialize(input);
        if (err != utils::DecodeError::None)
            return err;
        keyShare_ = std::move(inner);
        return utils::DecodeError::None;
    }
    case HandshakeType::HelloRetryRequestCode:
    {
        KeyShareHelloRetryRequest inner;
        const auto err = inner.deserialize(input);
        if (err != utils::DecodeError::None)
            return err;
        keyShare_ = std::move(inner);
        return utils::DecodeError::None;
    }
    default:
        return utils::DecodeError::LengthOutOfRange;
    }
}

KeyShare::KeyShare(crypto::GroupParams selectedGroup, const Key* serverKey)
    : keyShare_(KeyShareServerHello(selectedGroup, serverKey))
{
}

void KeyShare::setPublicKey(const Key* key)
{
    std::visit(
        [&](auto& inner)
        {
            using T = std::decay_t<decltype(inner)>;
            if constexpr (std::is_same_v<T, KeyShareServerHello>)
                inner.setPublicKey(key);
            else
                throw std::logic_error("setPublicKey(key): active form is not ServerHello");
        },
        keyShare_);
}

void KeyShare::setPublicKey(std::size_t idx, const Key* key)
{
    std::visit(
        [&](auto& inner)
        {
            using T = std::decay_t<decltype(inner)>;
            if constexpr (std::is_same_v<T, KeyShareClientHello>)
                inner.setPublicKey(idx, key);
            else
                throw std::logic_error("setPublicKey(idx, key): active form is not ClientHello");
        },
        keyShare_);
}

crypto::KeyPtr KeyShare::getPublicKey(std::size_t i) const
{
    return std::visit(
        [&](const auto& inner) -> crypto::KeyPtr
        {
            using T = std::decay_t<decltype(inner)>;
            if constexpr (std::is_same_v<T, KeyShareClientHello> || std::is_same_v<T, KeyShareServerHello>)
            {
                return inner.getPublicKey(i);
            }
            else
            {
                throw std::logic_error("getPublicKey: active form has no public key");
            }
        },
        keyShare_);
}

void KeyShare::offeredGroups(std::vector<crypto::GroupParams>& out) const
{
    std::visit(
        [&](const auto& inner)
        {
            inner.offeredGroups(out);
        },
        keyShare_);
}

crypto::GroupParams KeyShare::selectedGroup() const
{
    return std::visit(
        [](const auto& inner)
        {
            return inner.selectedGroup();
        },
        keyShare_);
}

void KeyShare::retryOffer(const KeyShare& hrr, const std::vector<crypto::GroupParams>& supportedGroups)
{
    std::visit(
        [&](auto& a, const auto& b)
        {
            using T1 = std::decay_t<decltype(a)>;
            using T2 = std::decay_t<decltype(b)>;
            if constexpr (std::is_same_v<T1, KeyShareClientHello> && std::is_same_v<T2, KeyShareHelloRetryRequest>)
            {
                const auto sel = b.selectedGroup();
                if (std::find(supportedGroups.begin(), supportedGroups.end(), sel) == supportedGroups.end())
                {
                    throw std::runtime_error("HRR selected_group was not advertised as supported");
                }
                a.retryOffer(sel);
            }
            else
            {
                throw std::runtime_error("retryOffer requires ClientHello + HRR");
            }
        },
        keyShare_,
        hrr.keyShare_);
}

} // namespace snet::tls