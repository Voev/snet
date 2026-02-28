#pragma once
#include <vector>
#include <casket/utils/exception.hpp>
#include <snet/crypto/group_params.hpp>
#include <snet/tls/types.hpp>
#include <snet/tls/exts/extension.hpp>
#include <snet/utils/data_reader.hpp>

namespace snet::tls
{

template <class T>
inline std::vector<T> ParseListItems(nonstd::span<const uint8_t> input, const char* name)
{
    utils::DataReader reader(name, input);
    uint16_t length = reader.get_uint16_t();

    casket::ThrowIfTrue(length % 2 == 1 || length == 0, "Bad encoding {} extension");

    std::vector<T> schemes;
    schemes.reserve(length / 2);
    while (length)
    {
        schemes.emplace_back(reader.get_uint16_t());
        length -= 2;
    }

    return schemes;
}

/**
 * Supported Groups Extension (RFC 7919)
 */
class SupportedGroups final : public Extension
{
public:
    static ExtensionCode staticType()
    {
        return ExtensionCode::SupportedGroups;
    }

    ExtensionCode type() const override
    {
        return staticType();
    }

    const std::vector<crypto::GroupParams>& groups() const
    {
        return groups_;
    }

    // Returns the list of groups we recognize as ECDH curves
    std::vector<crypto::GroupParams> getEcGroups() const
    {
        std::vector<crypto::GroupParams> ec;
        for (auto g : groups_)
        {
            if (g.isPureEccGroup())
            {
                ec.emplace_back(std::move(g));
            }
        }
        return ec;
    }

    // Returns the list of any groups in the FFDHE range
    std::vector<crypto::GroupParams> getDhGroups() const
    {
        std::vector<crypto::GroupParams> dh;
        for (auto g : groups_)
        {
            if (g.isInFfdheRange())
            {
                dh.emplace_back(std::move(g));
            }
        }
        return dh;
    }

    size_t serialize(Side side, nonstd::span<uint8_t> output) const override
    {
        (void)side;

        const uint16_t bytesSize = static_cast<uint16_t>(groups_.size() * 2);
        size_t i = 0;

        output[i++] = casket::get_byte<0>(bytesSize);
        output[i++] = casket::get_byte<1>(bytesSize);

        for (const auto& group : groups_)
        {
            auto wireCode = group.wireCode();
            output[i++] = casket::get_byte<0>(wireCode);
            output[i++] = casket::get_byte<1>(wireCode);
        }

        return i;
    }

    explicit SupportedGroups(std::vector<crypto::GroupParams> groups)
        : groups_(std::move(groups))
    {
    }

    SupportedGroups(Side, nonstd::span<const uint8_t> input)
        : groups_(ParseListItems<crypto::GroupParams>(input, "SupportedGroups"))
    {}

    bool empty() const override
    {
        return groups_.empty();
    }

private:
    std::vector<crypto::GroupParams> groups_;
};

} // namespace snet::tls