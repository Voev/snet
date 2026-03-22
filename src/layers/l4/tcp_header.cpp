#include <snet/layers/l4/tcp_header.hpp>
#include <snet/layers/packet.hpp>

namespace snet::layers
{

bool TCPHeader::initialize(const LayerInfo& layer, const Packet& packet) noexcept
{
    if (layer.protocol != g_ProtocolType)
    {
        return false;
    }
    if (layer.offset + sizeof(RawType) > packet.getDataLen())
    {
        return false;
    }
    header_ = reinterpret_cast<const RawType*>(packet.getData() + layer.offset);
    return true;
}

} // namespace snet::layers