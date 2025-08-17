#include <algorithm>
#include <utility>
#include <variant>

#include <snet/crypto/pointers.hpp>
#include <snet/crypto/asymm_key.hpp>

#include <snet/tls/exts/key_share.hpp>
#include <snet/utils/data_reader.hpp>
#include <snet/utils/data_writer.hpp>

#include <casket/utils/exception.hpp>
#include <casket/utils/load_store.hpp>

using namespace snet::crypto;

namespace snet::tls
{

KeyShareEntry::KeyShareEntry(const crypto::GroupParams groupParams)
    : groupParams_(groupParams)
{
}

void KeyShareEntry::setGroup(const GroupParams groupParams) noexcept
{
    groupParams_ = groupParams;
}

GroupParams KeyShareEntry::getGroup() const noexcept
{
    return groupParams_;
}

void KeyShareEntry::setPublicKey(const Key* key)
{
    if (groupParams_.isPureEccGroup())
    {
        keyExchange_ = AsymmKey::getEncodedPublicKey(key);
    }
    else
    {
        throw casket::RuntimeError("Unsupported key exchange algorithm");
    }
}

KeyPtr KeyShareEntry::getPublicKey() const
{
    KeyPtr publicKey = GroupParams::generateParams(groupParams_);
    AsymmKey::setEncodedPublicKey(publicKey, keyExchange_);
    return publicKey;
}

bool KeyShareEntry::empty() const noexcept
{
    return (groupParams_ == GroupParams::NONE) && keyExchange_.empty();
}

void KeyShareEntry::deserialize(utils::DataReader& reader)
{
    groupParams_ = static_cast<crypto::GroupParams>(reader.get_uint16_t());
    keyExchange_ = reader.get_tls_length_value(2);
}

size_t KeyShareEntry::serialize(nonstd::span<uint8_t> output) const
{
    casket::ThrowIfTrue(output.size_bytes() < 2, "Buffer too small");

    const uint16_t namedCurveID = groupParams_.wireCode();
    output[0] = casket::get_byte<0>(namedCurveID);
    output[1] = casket::get_byte<1>(namedCurveID);

    auto size = append_length_and_value(output.subspan(2), keyExchange_.data(), keyExchange_.size(), 2);
    size += 2;

    return size;
}

/// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/// ClientKeyShare
/// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

KeyShareClientHello::KeyShareClientHello(nonstd::span<const uint8_t> input)
{
    deserialize(input);
}

KeyShareClientHello::KeyShareClientHello(const std::vector<crypto::GroupParams>& supported)
{
    for (const auto group : supported)
    {
        clientKeyShares_.emplace_back(group);
    }
}

void KeyShareClientHello::retryOffer(const crypto::GroupParams toOffer)
{
    clientKeyShares_.clear();
    clientKeyShares_.emplace_back(toOffer);
}

std::vector<crypto::GroupParams> KeyShareClientHello::offeredGroups() const
{
    std::vector<crypto::GroupParams> offered_groups;
    offered_groups.reserve(clientKeyShares_.size());
    for (const auto& share : clientKeyShares_)
    {
        offered_groups.push_back(share.getGroup());
    }
    return offered_groups;
}

crypto::GroupParams KeyShareClientHello::selectedGroup() const
{
    throw std::invalid_argument("Client Hello Key Share does not select a group");
}

void KeyShareClientHello::setPublicKey(const size_t idx, const Key* key)
{
    clientKeyShares_[idx].setPublicKey(key);
}

crypto::KeyPtr KeyShareClientHello::getPublicKey(const size_t idx)
{
    return clientKeyShares_[idx].getPublicKey();
}

bool KeyShareClientHello::empty() const
{
    // RFC 8446 4.2.8
    //    Clients MAY send an empty client_shares vector in order to request
    //    group selection from the server, at the cost of an additional round
    //    trip [...].
    return false;
}

static inline bool CheckUnique(nonstd::span<const KeyShareEntry> entries, const KeyShareEntry& checkedEntry)
{
    return std::find_if(entries.begin(), entries.end(), [&](const auto& entry)
                        { return entry.getGroup() == checkedEntry.getGroup(); }) == entries.end();
}

void KeyShareClientHello::deserialize(nonstd::span<const uint8_t> input)
{
    utils::DataReader reader("ClientHello KeyShare", input);

    const auto length = reader.get_uint16_t();
    casket::ThrowIfTrue(reader.remaining_bytes() != length, "Invalid key share length");

    while (reader.has_remaining())
    {
        KeyShareEntry newEntry;
        newEntry.deserialize(reader);

        // RFC 8446 4.2.8
        //    Clients MUST NOT offer multiple KeyShareEntry values for the same
        //    group. [...]
        //    Servers MAY check for violations of these rules and abort the
        //    handshake with an "illegal_parameter" alert if one is violated.

        casket::ThrowIfFalse(CheckUnique(clientKeyShares_, newEntry),
                             "Received multiple key share entries for the same group");

        clientKeyShares_.emplace_back(std::move(newEntry));
    }

    reader.assert_done();
}

size_t KeyShareClientHello::serialize(nonstd::span<uint8_t> output) const
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

/// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/// KeyShare ServerHello
/// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

KeyShareServerHello::KeyShareServerHello(crypto::GroupParams group, const Key* serverKey)
{
    serverKeyShare_.setGroup(group);
    serverKeyShare_.setPublicKey(serverKey);
}

void KeyShareServerHello::setPublicKey(const Key* key)
{
    serverKeyShare_.setPublicKey(key);
}

crypto::KeyPtr KeyShareServerHello::getPublicKey(size_t)
{
    return serverKeyShare_.getPublicKey();
}

std::vector<crypto::GroupParams> KeyShareServerHello::offeredGroups() const
{
    return {selectedGroup()};
}

crypto::GroupParams KeyShareServerHello::selectedGroup() const
{
    return serverKeyShare_.getGroup();
}

bool KeyShareServerHello::empty() const
{
    return serverKeyShare_.empty();
}

void KeyShareServerHello::deserialize(nonstd::span<const uint8_t> input)
{
    utils::DataReader reader("ServerHello KeyShare", input);
    serverKeyShare_.deserialize(reader);
    reader.assert_done();
}

size_t KeyShareServerHello::serialize(nonstd::span<uint8_t> output) const
{
    return serverKeyShare_.serialize(output);
}

/// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/// KeyShare HRR
/// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

KeyShareHelloRetryRequest::KeyShareHelloRetryRequest(crypto::GroupParams selectedGroup)
    : selectedGroup_(selectedGroup)
{
}

crypto::GroupParams KeyShareHelloRetryRequest::selectedGroup() const
{
    return selectedGroup_;
}

std::vector<crypto::GroupParams> KeyShareHelloRetryRequest::offeredGroups() const
{
    throw std::logic_error("Hello Retry Request never offers any key exchange groups");
}

bool KeyShareHelloRetryRequest::empty() const
{
    return (selectedGroup_ == crypto::GroupParams::NONE);
}

void KeyShareHelloRetryRequest::deserialize(nonstd::span<const uint8_t> input)
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

size_t KeyShareHelloRetryRequest::serialize(nonstd::span<uint8_t> output) const
{
    auto code = selectedGroup_.wireCode();
    output[0] = casket::get_byte<0>(code);
    output[1] = casket::get_byte<1>(code);
    return 2;
}

/// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/// KeyShare
/// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

KeyShare::KeyShare(nonstd::span<const uint8_t> input, HandshakeType messageType)
{
    if (messageType == HandshakeType::ClientHelloCode)
    {
        auto& inner = keyShare_.emplace<KeyShareClientHello>();
        inner.deserialize(input);
    }
    else if (messageType == HandshakeType::ServerHelloCode)
    {
        auto& inner = keyShare_.emplace<KeyShareServerHello>();
        inner.deserialize(input);
    }
    else if (messageType == HandshakeType::HelloRetryRequestCode)
    {
        auto& inner = keyShare_.emplace<KeyShareHelloRetryRequest>();
        inner.deserialize(input);
    }
    else
    {
        throw casket::RuntimeError("cannot create a KeyShare extension for message of type: {}", toString(messageType));
    }
}

size_t KeyShare::serialize(Side whoami, nonstd::span<uint8_t> output) const
{
    (void)whoami;
    return std::visit([output](const auto& keyShare) { return keyShare.serialize(output); }, keyShare_);
}

KeyShare::KeyShare(const std::vector<GroupParams>& supportedGroups)
    : keyShare_(KeyShareClientHello(supportedGroups))
{
}

KeyShare::KeyShare(GroupParams selectedGroup, const Key* serverKey)
    : keyShare_(KeyShareServerHello(selectedGroup, serverKey))
{
}

KeyShare::KeyShare(GroupParams selectedGroup)
    : keyShare_(KeyShareHelloRetryRequest(selectedGroup))
{
}

KeyShare::~KeyShare() noexcept
{
}

bool KeyShare::empty() const
{
    return std::visit([](const auto& inner) { return inner.empty(); }, keyShare_);
}

std::vector<GroupParams> KeyShare::offeredGroups() const
{
    return std::visit([](const auto& inner) { return inner.offeredGroups(); }, keyShare_);
}

GroupParams KeyShare::selectedGroup() const
{
    return std::visit([](const auto& inner) { return inner.selectedGroup(); }, keyShare_);
}

void KeyShare::setPublicKey(const Key* key)
{
    return std::visit(
        [&](auto&& inner)
        {
            using T = std::decay_t<decltype(inner)>;
            if constexpr (std::is_same_v<T, KeyShareServerHello>)
            {
                inner.setPublicKey(key);
            }
            else
            {
                throw std::logic_error("unsupported operation");
            }
        },
        keyShare_);
}

void KeyShare::setPublicKey(const size_t idx, const Key* key)
{
    return std::visit(
        [&](auto&& inner)
        {
            using T = std::decay_t<decltype(inner)>;
            if constexpr (std::is_same_v<T, KeyShareClientHello>)
            {
                inner.setPublicKey(idx, key);
            }
            else
            {
                throw std::logic_error("unsupported operation");
            }
        },
        keyShare_);
}

crypto::KeyPtr KeyShare::getPublicKey(size_t i)
{
    return std::visit(
        [&](auto&& inner) -> crypto::KeyPtr
        {
            using T = std::decay_t<decltype(inner)>;
            if constexpr (std::is_same_v<T, KeyShareClientHello>)
            {
                return inner.getPublicKey(i);
            }
            else if constexpr (std::is_same_v<T, KeyShareServerHello>)
            {
                return inner.getPublicKey(i);
            }
            else
            {
                throw std::logic_error("unsupported operation");
            }
            return nullptr;
        },
        keyShare_);
}

void KeyShare::retryOffer(const KeyShare& retryRequestKeyShare, const std::vector<GroupParams>& supportedGroups)
{
    std::visit(
        [&](auto&& arg1, auto&& arg2)
        {
            using T1 = std::decay_t<decltype(arg1)>;
            using T2 = std::decay_t<decltype(arg2)>;

            if constexpr (std::is_same_v<T1, KeyShareClientHello> && std::is_same_v<T2, KeyShareHelloRetryRequest>)
            {
                auto selected = arg2.selectedGroup();
                // RFC 8446 4.2.8
                //    [T]he selected_group field [MUST correspond] to a group which was provided in
                //    the "supported_groups" extension in the original ClientHello
                if (std::find(supportedGroups.begin(), supportedGroups.end(), selected) != supportedGroups.end())
                {
                    throw std::runtime_error("group was not advertised as supported");
                }

                return arg1.retryOffer(selected);
            }
            else
            {
                throw std::runtime_error("can only retry with HelloRetryRequest on a ClientHello KeyShare");
            }
        },
        keyShare_, retryRequestKeyShare.keyShare_);
}

} // namespace snet::tls