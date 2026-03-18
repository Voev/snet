#include <snet/layers/l4/tcp_header.hpp>
#include <snet/layers/packet.hpp>

namespace snet::layers
{

bool TCPHeader::initialize(const LayerInfo& layer, const Packet& packet) noexcept
{
    if (layer.protocol != protocol_type)
    {
        return false;
    }
    if (layer.offset + sizeof(raw_type) > packet.getDataLen())
    {
        return false;
    }
    m_Header = reinterpret_cast<const raw_type*>(packet.getData() + layer.offset);
    return true;
}

} // namespace snet::layers