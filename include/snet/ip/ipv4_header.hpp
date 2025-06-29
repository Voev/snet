#pragma once
#include <cstdint>
#include <vector>
#include <casket/utils/endianness.hpp>
#include <snet/ip/ipv4_address.hpp>

namespace snet::ip {

class IPv4Header {
public:
    /**
     * Type used to represent the different IP flags.
     */
    enum Flags {
        FLAG_RESERVED = 4,
        DONT_FRAGMENT = 2,
        MORE_FRAGMENTS = 1
    };

    /**
     * \brief Constructor for building the IP PDU.
     *
     * Both the destination and source IP address can be supplied.
     * By default, those fields are initialized using the IP
     * address 0.0.0.0.
     *
     * \param ip_dst The destination ip address(optional).
     * \param ip_src The source ip address(optional).
     */
    IPv4Header(const IPv4Address& ip_dst = IPv4Address(), const IPv4Address& ip_src = IPv4Address());

    /**
     * \brief Constructs an IP object from a buffer and adds all
     * identifiable PDUs found in the buffer as children of this
     * one.
     *
     * If there is not enough size for an IP header, a
     * malformed_packet exception is thrown.
     *
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    IPv4Header(const uint8_t* buffer, uint32_t total_sz);

    void read(const uint8_t* buffer, uint32_t total_sz);

    /* Getters */
    /**
     * \brief Getter for the header length field.
     *
     * \return The number of dwords the header occupies in an uin8_t.
     */
    uint8_t headerLen() const {
        return header_.ihl;
    }

    /**
     * \brief Getter for the type of service field.
     *
     * \return The this IP PDU's type of service.
     */
    uint8_t tos() const {
        return header_.tos;
    }

    /**
     * \brief Getter for the total length field.
     *
     * \return The total length of this IP PDU.
     */
    uint16_t totalLen() const {
        return casket::be_to_host(header_.tot_len);
    }

    /**
     * \brief Getter for the id field.
     *
     * \return The id for this IP PDU.
     */
    uint16_t id() const {
        return casket::be_to_host(header_.id);
    }

    /**
     * Indicates whether this PDU is fragmented.
     *
     * \return true if this PDU is fragmented, false otherwise.
     */
    bool isFragmented() const;

    /**
     * \brief Getter for the fragment offset field.
     *
     * This will return the fragment offset field, as present in the packet,
     * which indicates the offset of this fragment in blocks of 8 bytes.
     *
     * \return The fragment offset, measured in units of 8 byte blocks
     */
    uint16_t fragmentOffset() const {
        return casket::be_to_host(header_.frag_off) & 0x1fff;
    }

    /**
     * \brief Getter for the flags field.
     *
     * \return The IP flags field
     */
    Flags flags() const {
        return static_cast<Flags>(casket::be_to_host(header_.frag_off) >> 13);
    }

    /**
     * \brief Getter for the time to live field.
     *
     * \return The time to live for this IP PDU.
     */
    uint8_t ttl() const {
        return header_.ttl;
    }

    /**
     * \brief Getter for the protocol field.
     *
     * \return The protocol for this IP PDU.
     */
    uint8_t protocol() const {
        return header_.protocol;
    }

    /**
     * \brief Getter for the checksum field.
     *
     * \return The checksum for this IP PDU.
     */
    uint16_t checksum() const {
        return casket::be_to_host(header_.check);
    }

    /**
     * \brief Getter for the source address field.
     *
     * \return The source address for this IP PDU.
     */
    IPv4Address srcAddr() const {
        return IPv4Address(header_.saddr);
    }

    /**
     * \brief Getter for the destination address field.
     * \return The destination address for this IP PDU.
     */
    IPv4Address dstAddr() const {
        return IPv4Address(header_.daddr);
    }

    /**
     * \brief Getter for the version field.
     * \return The version for this IP PDU.
     */
    uint8_t version() const {
        return header_.version;
    }

    /* Setters */
    void initFields();

    /**
     * \brief Setter for the version field.
     *
     * \param ver The version field to be set.
     */
    void version(uint8_t ver);

    void headerLen(uint8_t new_head_len);

    /**
     * \brief Setter for the type of service field.
     *
     * \param new_tos The new type of service.
     */
    void tos(uint8_t new_tos);

    void totalLen(uint16_t new_tot_len);

    /**
     * \brief Setter for the flags field.
     *
     * \param new_flags The new IP flags field value.
     */
    void flags(Flags new_flags);

    /**
     * \brief Setter for the id field.
     *
     * \param new_id The new id.
     */
    void id(uint16_t new_id);

    /**
     * \brief Setter for the fragment offset field.
     *
     * The value provided is measured in units of 8 byte blocks. This means that
     * if you want this packet to have a fragment offset of <i>X</i>,
     * you need to provide <i>X / 8</i> as the argument to this method.
     *
     * \param new_frag_off The new fragment offset, measured in units of 8 byte blocks.
     */
    void fragmentOffset(uint16_t new_frag_off);

    /**
     * \brief Setter for the time to live field.
     *
     * \param new_ttl The new time to live.
     */
    void ttl(uint8_t new_ttl);

    /**
     * \brief Setter for the protocol field.
     *
     * Note that this protocol will be overwritten using the
     * inner_pdu's protocol type during serialization unless the IP
     * datagram is fragmented.
     *
     * If the packet is fragmented and was originally sniffed, the
     * original protocol type will be kept when serialized.
     *
     * If this packet has been crafted manually and the inner_pdu
     * is, for example, a RawPDU, then setting the protocol yourself
     * is necessary.
     *
     * \param new_protocol The new protocol.
     */
    void protocol(uint8_t new_protocol);

    void checksum(uint16_t new_check);

    /**
     * \brief Setter for the source address field.
     *
     * \param ip The source address to be set.
     */
    void srcAddr(const IPv4Address& ip);

    /**
     * \brief Setter for the destination address field.
     *
     * \param ip The destination address to be set.
     */
    void dstAddr(const IPv4Address& ip);

private:

    struct ipv4_header {
#if SNET_IS_LITTLE_ENDIAN
        uint8_t ihl : 4, version : 4;
#else
        uint8_t version : 4, ihl : 4;
#endif
        uint8_t tos;
        uint16_t tot_len;
        uint16_t id;
        uint16_t frag_off;
        uint8_t ttl;
        uint8_t protocol;
        uint16_t check;
        uint32_t saddr;
        uint32_t daddr;
    } __attribute__((packed));

    ipv4_header header_;
};

} // namespace snet::net
