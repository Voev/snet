#include <cstring>
#include <snet/tcp/tcp_header.hpp>
#include <snet/utils/format.hpp>
#include <snet/stream/memory_reader.hpp>

using std::pair;
using std::vector;

namespace snet::tcp {

const uint16_t TcpHeader::DEFAULT_WINDOW = 32678;

TcpHeader::TcpHeader(uint16_t dp, uint16_t sp)
    : header_() {
    dport(dp);
    sport(sp);
    data_offset(sizeof(tcp_header) / sizeof(uint32_t));
    window(DEFAULT_WINDOW);
}

TcpHeader::TcpHeader(const uint8_t* buffer, uint32_t total_sz) {
    read(buffer, total_sz);
}

void TcpHeader::read(const uint8_t* buffer, uint32_t total_sz) {
    snet::stream::MemoryReader stream(buffer, total_sz);
    stream.read(header_);
}

uint32_t TcpHeader::header_size() const {
    return sizeof(header_);
}

void TcpHeader::dport(uint16_t new_dport) {
    header_.dport = utils::host_to_be(new_dport);
}

void TcpHeader::sport(uint16_t new_sport) {
    header_.sport = utils::host_to_be(new_sport);
}

void TcpHeader::seq(uint32_t new_seq) {
    header_.seq = utils::host_to_be(new_seq);
}

void TcpHeader::ack(uint32_t ack) {
    header_.ack = utils::host_to_be(ack);
}

void TcpHeader::window(uint16_t new_window) {
    header_.window = utils::host_to_be(new_window);
}

void TcpHeader::checksum(uint16_t new_check) {
    header_.check = utils::host_to_be(new_check);
}

void TcpHeader::urg_ptr(uint16_t new_urg_ptr) {
    header_.urg_ptr = utils::host_to_be(new_urg_ptr);
}

void TcpHeader::data_offset(uint8_t new_doff) {
    this->header_.doff = new_doff;
}

uint8_t TcpHeader::get_flag(Flags tcp_flag) const {
    switch (tcp_flag) {
        case FIN:
            return header_.flags.fin;
            break;
        case SYN:
            return header_.flags.syn;
            break;
        case RST:
            return header_.flags.rst;
            break;
        case PSH:
            return header_.flags.psh;
            break;
        case ACK:
            return header_.flags.ack;
            break;
        case URG:
            return header_.flags.urg;
            break;
        case ECE:
            return header_.flags.ece;
            break;
        case CWR:
            return header_.flags.cwr;
            break;
        default:
            break;
    };
    return 0;
}

uint16_t TcpHeader::flags() const {
    return (header_.res1 << 8) | header_.flags_8;
}

bool TcpHeader::has_flags(uint16_t check_flags) const {
    return (flags() & check_flags) == check_flags;
}

void TcpHeader::set_flag(Flags tcp_flag, uint8_t value) {
    switch (tcp_flag) {
        case FIN:
            header_.flags.fin = value;
            break;
        case SYN:
            header_.flags.syn = value;
            break;
        case RST:
            header_.flags.rst = value;
            break;
        case PSH:
            header_.flags.psh = value;
            break;
        case ACK:
            header_.flags.ack = value;
            break;
        case URG:
            header_.flags.urg = value;
            break;
        case ECE:
            header_.flags.ece = value;
            break;
        case CWR:
            header_.flags.cwr = value;
            break;
        default:
            break;
    };
}

void TcpHeader::flags(uint16_t value) {
    header_.res1 = (value >> 8) & 0x0f;
    header_.flags_8 = value & 0xff;
}

} // namespace snet::net