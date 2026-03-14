#pragma once
#include <vector>
#include <string>
#include <snet/tls/types.hpp>
#include <snet/crypto/exception.hpp>

namespace snet::tls
{

class ConfigBuilder
{
public:
    struct Command
    {
        std::string name;
        std::string value;
    };

    using CommandList = std::vector<Command>;

private:
    CommandList commands_;

public:
    ConfigBuilder() = default;

    ConfigBuilder& addCommand(const std::string& cmd, const std::string& value)
    {
        commands_.push_back({cmd, value});
        return *this;
    }

    void apply(Settings& settings, unsigned int flags) const
    {
        if (commands_.empty())
        {
            return;
        }

        SslConfigPtr cctx(SSL_CONF_CTX_new());
        crypto::ThrowIfFalse(cctx, "Error: Failed to create configuration context");

        SSL_CONF_CTX_set_ssl_ctx(cctx, settings.ctx_);
        SSL_CONF_CTX_set_flags(cctx, flags);

        for (const auto& cmd : commands_)
        {
            crypto::ThrowIfFalse(0 < SSL_CONF_cmd(cctx, cmd.name.c_str(), cmd.value.c_str()));
        }

        crypto::ThrowIfFalse(SSL_CONF_CTX_finish(cctx));
    }

    void clear()
    {
        commands_.clear();
    }

    ConfigBuilder& copyFrom(const ConfigBuilder& other)
    {
        commands_.insert(commands_.end(), other.commands_.begin(), other.commands_.end());
        return *this;
    }
};

} // namespace snet::tls
