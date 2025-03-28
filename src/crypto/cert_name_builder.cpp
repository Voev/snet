#include <snet/crypto/cert_name_builder.hpp>

#include <snet/crypto/exception.hpp>

#include <casket/utils/string.hpp>
#include <casket/utils/exception.hpp>

using namespace casket;

namespace snet::crypto
{

CertNameBuilder::CertNameBuilder()
{
    reset();
}

CertNameBuilder& CertNameBuilder::addEntry(const std::string& field, const std::string& value)
{
    auto data = reinterpret_cast<const unsigned char*>(value.data());
    int sz = static_cast<int>(value.size());

    crypto::ThrowIfFalse(
        X509_NAME_add_entry_by_txt(name(), field.data(), MBSTRING_UTF8, data, sz, -1, -1));
    return *this;
}

CertNamePtr CertNameBuilder::build()
{
    auto result = std::move(name_);
    reset();
    return result;
}

void CertNameBuilder::reset()
{
    name_.reset(X509_NAME_new());
    crypto::ThrowIfTrue(name_ == nullptr);
}

CertNamePtr CertNameBuilder::fromString(const std::string& DN)
{
    casket::utils::ThrowIfTrue(DN.empty(), "DN can't be empty");

    CertNameBuilder builder;

    auto&& options = casket::utils::split(DN, ";");
    for (auto&& option : options)
    {
        auto&& parts = ::utils::split(option, "=");

        ::utils::ThrowIfTrue(parts.size() != 2,
                             "Invalid format of DN: '" + DN +
                                 "'. Expected format: <ENTRY=VALUE>[;<ENTRY=VALUE>...]");

        builder.addEntry(parts[0], parts[1]);
    }

    return CertNamePtr(builder.build());
}

} // namespace snet::crypto