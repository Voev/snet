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
    KeyPtr publicKey(GenerateGroupParams(groupParams_));
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