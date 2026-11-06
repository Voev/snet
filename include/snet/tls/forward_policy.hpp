#pragma once
#include <snet/tls/policy.hpp>
#include <snet/tls/msgs/client_hello.hpp>

#include <snet/tls/session.hpp>

namespace snet::tls
{

class ForwardClientHelloPolicy final : public Policy
{
public:
    ForwardClientHelloPolicy(const ClientHello& src, const Session& processedOn) noexcept
    {
        const auto& exts = processedOn.getClientExtensions();

        // SNI: view into ServerName, no copy.
        if (exts.has(ExtensionCode::ServerNameIndication))
            sni_ = exts.get<ServerNameIndicator>()->getHostname();

        // Versions.
        if (exts.has(ExtensionCode::SupportedVersions))
        {
            for (auto v : exts.get<SupportedVersions>()->versions())
                if (versionsCount_ < versions_.size())
                    versions_[versionsCount_++] = v;
        }
        else
        {
            versions_[0] = src.version;
            versionsCount_ = 1;
        }

        // Cipher suites.
        auto& mgr = CipherSuiteManager::getInstance();
        for (std::size_t i = 0; i + 1 < src.suites.size() && cipherSuitesCount_ < cipherSuites_.size(); i += 2)
        {
            const std::uint16_t id =
                static_cast<std::uint16_t>((std::uint16_t(src.suites[i]) << 8) | src.suites[i + 1]);
            if (auto* cs = mgr.getCipherSuiteById(id))
                cipherSuites_[cipherSuitesCount_++] = cs;
        }

        // Groups.
        if (exts.has(ExtensionCode::SupportedGroups))
        {
            for (auto g : exts.get<SupportedGroups>()->groups())
                if (groupParamsCount_ < groupParams_.size())
                    groupParams_[groupParamsCount_++] = g;
        }

        // Signature algorithms.
        if (exts.has(ExtensionCode::SignatureAlgorithms))
        {
            for (auto s : exts.get<SignatureAlgorithms>()->supportedSchemes())
                if (sigAlgsCount_ < sigAlgs_.size())
                    sigAlgs_[sigAlgsCount_++] = static_cast<std::uint16_t>(s.wireCode());
        }
    }

    nonstd::string_view serverNameIndication() const noexcept override
    {
        return sni_;
    }
    nonstd::span<const ProtocolVersion> supportedVersion() const noexcept override
    {
        return {versions_.data(), versionsCount_};
    }
    nonstd::span<const CipherSuite*> offeredCipherSuites() noexcept override
    {
        return nonstd::span{cipherSuites_.data(), cipherSuitesCount_};
    }
    nonstd::span<const crypto::GroupParams> offeredGroupParams() const noexcept override
    {
        return {groupParams_.data(), groupParamsCount_};
    }
    nonstd::span<std::uint8_t> clientSessionId() const noexcept override
    {
        return {};
    }
    nonstd::span<nonstd::string_view> alpnProtocols() const noexcept override
    {
        return {};
    }
    nonstd::span<std::uint16_t> signatureAlgorithms() noexcept override
    {
        return {sigAlgs_.data(), sigAlgsCount_};
    }

    bool useEncryptThenMac() const noexcept override
    {
        return false;
    }
    bool useExtendedMasterSecret() const noexcept override
    {
        return true;
    }
    bool useSessionTicket() const noexcept override
    {
        return false;
    }
    bool useRenegotiationInfo() const noexcept override
    {
        return true;
    }

private:
    std::string sni_;

    std::array<ProtocolVersion, 8> versions_{};
    std::array<const CipherSuite*, 64> cipherSuites_{};
    std::array<crypto::GroupParams, 16> groupParams_{};
    std::array<std::uint16_t, 32> sigAlgs_{};

    std::uint8_t versionsCount_ = 0;
    std::uint8_t cipherSuitesCount_ = 0;
    std::uint8_t groupParamsCount_ = 0;
    std::uint8_t sigAlgsCount_ = 0;
};

} // namespace snet::tls