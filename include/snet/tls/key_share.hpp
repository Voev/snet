#pragma once
#include <vector>
#include <snet/tls/extensions.hpp>
#include <snet/utils/data_reader.hpp>


namespace snet::tls
{

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

    KeyShare(utils::DataReader& reader, uint16_t extensionSize, HandshakeType messageType);

    // constructor used for ClientHello msg
    KeyShare(const std::vector<GroupParams>& supported);

    // constructor used for ServerHello
    // (called via create_as_encapsulation())
    KeyShare(GroupParams selected_group, const Key* serverKey);

    // constructor used for HelloRetryRequest msg
    KeyShare(GroupParams selected_group);

    ~KeyShare() noexcept;

    size_t serialize(Side whoami, std::span<uint8_t> buffer) const override;

    bool empty() const override;

    void setPublicKey(const size_t idx, const Key* key);

    void setPublicKey(const Key* key);

    crypto::KeyPtr getPublicKey(size_t i = 0);
    /**
     * Update a ClientHello's Key_Share to comply with a HelloRetryRequest.
     *
     * This will create new Key_Share_Entries and should only be called on a ClientHello Key_Share with a
     * HelloRetryRequest Key_Share.
     */
    void retry_offer(const KeyShare& retry_request_keyshare, const std::vector<GroupParams>& supported_groups);

    /**
     * @return key exchange groups the peer offered key share entries for
     */
    std::vector<GroupParams> offered_groups() const;

    /**
     * @return key exchange group that was selected by a Hello Retry Request
     */
    GroupParams selected_group() const;

private:
    class KeyShareImpl;
    std::unique_ptr<KeyShareImpl> impl_;
};

} // namespace snet::tls
