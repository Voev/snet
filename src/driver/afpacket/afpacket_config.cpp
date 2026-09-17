#include <casket/log/log.hpp>

#include "afpacket_types.hpp"
#include "afpacket_config.hpp"

#include <linux/if.h>
#include <linux/if_packet.h>

namespace snet::driver
{

bool AFPacketConfig::parse(const snet::io::Config& cfg)
{
    snapLen = cfg.getSnaplen();
    timeoutMs = cfg.getTimeout();
    if (timeoutMs == 0)
        timeoutMs = -1;

    const std::string& devs = cfg.getInput();
    if (devs.empty() || devs.front() == ':' || devs.back() == ':')
    {
        CSK_LOG_ERROR("invalid interface specification: '%s'", devs.c_str());
        return false;
    }

    size_t pos = 0;
    while (pos < devs.size())
    {
        size_t colon = devs.find(':', pos);
        if (colon == std::string::npos)
            colon = devs.size();
        if (colon > pos)
        {
            std::string name = devs.substr(pos, colon - pos);
            if (name.size() >= IFNAMSIZ)
            {
                CSK_LOG_ERROR("interface name too long: '%s'", name.c_str());
                return false;
            }
            devices.push_back(std::move(name));
        }
        pos = colon + 1;
    }

    if (devices.empty())
    {
        CSK_LOG_ERROR("no interfaces specified");
        return false;
    }
    if (devices.size() > kMaxInterfaces)
    {
        CSK_LOG_ERROR("using more than %zu interfaces is not supported", kMaxInterfaces);
        return false;
    }

    for (const auto& kv : cfg.getParameters())
    {
        const std::string& key = kv.first;
        const std::string& value = kv.second;

        if (key == "buffer_size_mb")
        {
            bufferSizeMb = static_cast<uint32_t>(std::strtoul(value.c_str(), nullptr, 10));
        }
        else if (key == "debug")
        {
            debug = true;
        }
        else if (key == "use_tx_ring")
        {
            useTxRing = true;
        }
        else if (key == "fanout_type")
        {
            if (value == "hash")
                fanout.type = PACKET_FANOUT_HASH;
            else if (value == "lb")
                fanout.type = PACKET_FANOUT_LB;
            else if (value == "cpu")
                fanout.type = PACKET_FANOUT_CPU;
            else if (value == "rollover")
                fanout.type = PACKET_FANOUT_ROLLOVER;
            else if (value == "rnd")
                fanout.type = PACKET_FANOUT_RND;
            else if (value == "qm")
                fanout.type = PACKET_FANOUT_QM;
            else
            {
                CSK_LOG_ERROR("unrecognized argument for %s: '%s'", key.c_str(), value.c_str());
                return false;
            }
            fanout.enabled = true;
        }
        else if (key == "fanout_flag")
        {
            if (value == "rollover")
                fanout.flags |= PACKET_FANOUT_FLAG_ROLLOVER;
            else if (value == "defrag")
                fanout.flags |= PACKET_FANOUT_FLAG_DEFRAG;
            else
            {
                CSK_LOG_ERROR("unrecognized argument for %s: '%s'", key.c_str(), value.c_str());
                return false;
            }
        }
    }

    return true;
}

} // namespace snet::driver::afpacket