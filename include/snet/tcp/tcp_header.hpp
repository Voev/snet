#pragma once
#include <string>
#include <cstdint>
#include <arpa/inet.h>

#include <vector>
#include <stdint.h>
#include <utility>
#include <snet/utils/macros.hpp>
#include <snet/utils/endianness.hpp>

namespace snet::tcp {

enum Flags { FIN = 1, SYN = 2, RST = 4, PSH = 8, ACK = 16, URG = 32, ECE = 64, CWR = 128 };

/**
 * \class TCP
 * \brief Represents a TCP PDU.
 *
 * This class represents a TCP PDU.
 *
 * When sending TCP PDUs, the checksum is calculated automatically
 * every time you send the packet.
 *
 * While sniffing, the payload sent in each packet will be wrapped
 * in a RawPDU, which is set as the TCP object's inner_pdu. Therefore,
 * if you are sniffing and want to see the TCP packet's payload,
 * you need to do the following:
 *
 * \code
 * // Get a packet from somewhere.
 * TCP tcp = ...;
 *
 * // Extract the RawPDU object.
 * const RawPDU& raw = tcp.rfind_pdu<RawPDU>();
 *
 * // Finally, take the payload (this is a vector<uint8_t>)
 * const RawPDU::payload_type& payload = raw.payload();
 * \endcode
 *
 * \sa RawPDU
 */

class TcpHeader {
public:
    /**
     * \brief TCP flags enum.
     *
     * These flags identify those supported by the TCP PDU.
     */

    /**
     * \brief TCP options enum.
     *
     * This enum defines option types supported by TCP PDU.
     */
    enum OptionTypes {
        EOL = 0,
        NOP = 1,
        MSS = 2,
        WSCALE = 3,
        SACK_OK = 4,
        SACK = 5,
        TSOPT = 8,
        ALTCHK = 14,
        RFC_EXPERIMENT_1 = 253,
        RFC_EXPERIMENT_2 = 254
    };

    /**
     * \brief TCP constructor.
     *
     * Creates an instance of TCP. Destination and source port can
     * be provided, otherwise both will be 0.
     *
     * \param dport Destination port.
     * \param sport Source port.
     * */
    TcpHeader(uint16_t dport = 0, uint16_t sport = 0);

    /**
     * \brief Constructs TCP object from a buffer.
     *
     * If there is not enough size for a TCP header, or any of the
     * TLV options are malformed, a malformed_packet exception is
     * thrown.
     *
     * Any extra data will be stored in a RawPDU.
     *
     * \param buffer The buffer from which this PDU will be constructed.
     * \param total_sz The total size of the buffer.
     */
    TcpHeader(const uint8_t* buffer, uint32_t total_sz);

    void read(const uint8_t* buffer, uint32_t total_sz);

    /**
     * \brief Getter for the source port field.
     *
     * \return The source port field value.
     */
    uint16_t sport() const {
        return utils::be_to_host(header_.sport);
    }

    /**
     * \brief Getter for the destination port field.
     *
     * \return The destination port field value.
     */
    uint16_t dport() const {
        return utils::be_to_host(header_.dport);
    }

    /**
     * \brief Getter for the sequence number field.
     *
     * \return The sequence number field value.
     */
    uint32_t seq() const {
        return utils::be_to_host(header_.seq);
    }

    /**
     * \brief Getter for the acknowledge number field.
     *
     * \return The acknowledge number field value.
     */
    uint32_t ack() const {
        return utils::be_to_host(header_.ack);
    }

    /**
     * \brief Getter for the window size field.
     *
     * \return The window size field value.
     */
    uint16_t window() const {
        return utils::be_to_host(header_.window);
    }

    /**
     * \brief Getter for the checksum field.
     *
     * \return The checksum field value.
     */
    uint16_t checksum() const {
        return utils::be_to_host(header_.check);
    }

    /**
     * \brief Getter for the urgent pointer field.
     *
     * \return The urgent pointer field value.
     */
    uint16_t urg_ptr() const {
        return utils::be_to_host(header_.urg_ptr);
    }

    /**
     * \brief Getter for the data offset field.
     *
     * \return The data offset field value (bits count).
     */
    uint8_t data_offset() const {
        return header_.doff;
    }

    /**
     * \brief Gets the value of a flag.
     *
     * This method gets the value of a specific flag. If you
     * want to check for multiple flags at the same time,
     * use TCP::flags.
     *
     * If you want to check if this PDU has the SYN flag on,
     * you can do it like this:
     *
     * \code
     * // Get a TCP packet from somewhere.
     * TCP tcp = ...;
     *
     * if(tcp.get_flag(TCP::SYN)) {
     *     // The SYN flag is on!
     * }
     * \endcode
     *
     * \sa TCP::flags
     * \param tcp_flag The polled flag.
     * \return The value of the flag.
     */
    uint8_t get_flag(Flags tcp_flag) const;

    /**
     *
     * \brief Gets the flags' values.
     *
     * All of the set flags will be joined together into
     * a 12 bit value. This way, you can check for multiple
     * flags at the same time:
     *
     * \code
     * TCP tcp = ...;
     * if(tcp.flags() == (TCP::SYN | TCP::ACK)) {
     *     // It's a SYN+ACK, but not SYN+ACK+ECN!
     * }
     * \endcode
     *
     * \return The value of the flags field.
     */
    uint16_t flags() const;

    /**
     * \brief Check if the given flags are set.
     *
     * \code
     * TCP tcp = ...;
     * if(tcp.has_flags(TCP::SYN | TCP::ACK)) {
     *     // It's a SYN+ACK, but it also possible that other flags are set!
     *     // it is equivalent to: (tcp.flags() & (TCP::SYN | TCP::ACK)) == (TCP::SYN | TCP::ACK)
     * }
     * \endcode
     *
     * \param check_flags
     * \return true if all check_flags are set
     */
    bool has_flags(uint16_t check_flags) const;

    /* Setters */

    /**
     * \brief Setter for the destination port field.
     *
     * \param new_dport The new destination port.
     */
    void dport(uint16_t new_dport);

    /**
     * \brief Setter for the source port field.
     *
     * \param new_sport The new source port.
     */
    void sport(uint16_t new_sport);

    /**
     * \brief Setter for the sequence number.
     *
     * \param new_seq The new sequence number.
     */
    void seq(uint32_t new_seq);

    /**
     * \brief Setter for the acknowledge number.
     *
     * \param ack The new acknowledge number.
     */
    void ack(uint32_t ack);

    /**
     * \brief Setter for the window size.
     *
     * \param new_window The new window size.
     */
    void window(uint16_t new_window);

    /**
     * \brief Setter for the urgent pointer field.
     *
     * \param new_urg_ptr The new urgent pointer.
     */
    void urg_ptr(uint16_t new_urg_ptr);

    /**
     * \brief Setter for the data offset pointer field.
     *
     * \param new_doff The new data offset pointer.
     */
    void data_offset(uint8_t new_doff);

    /**
     * \brief Set a TCP flag value.
     *
     * \param tcp_flag The flag to be set.
     * \param value The new value for this flag. Must be 0 or 1.
     */
    void set_flag(Flags tcp_flag, uint8_t value);

    /**
     * \brief Sets the value of the flag fields.
     *
     * This method can be used to set several flags at the
     * same time.
     *
     * \code
     * // Get a TCP packet from somewhere and set the flags to SYN && ACK
     * TCP tcp = ...;
     * tcp.flags(TCP::SYN | TCP::ACK);
     *
     * // Now also set the PSH flag, without modifying
     * // the rest of the flags.
     * tcp.flags(tcp.flags() | TCP::PSH);
     * \endcode
     *
     * \param value The new value of the flags.
     */
    void flags(uint16_t value);

    /**
     * \brief Returns the header size.
     *
     * This method overrides PDU::header_size. This size includes the
     * payload and options size.
     *
     * \sa PDU::header_size
     */
    uint32_t header_size() const;

    void checksum(uint16_t new_check);

    std::string toString() const;

private:
#if SNET_IS_LITTLE_ENDIAN
    struct flags_type {
        uint8_t fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
    } __attribute__((packed));
#else
    struct flags_type {
        uint8_t cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1, fin : 1;
    } __attribute__((packed));
#endif

    struct tcp_header {
        uint16_t sport;
        uint16_t dport;
        uint32_t seq;
        uint32_t ack;
#if SNET_IS_LITTLE_ENDIAN
        uint8_t res1 : 4, doff : 4;
#else
        uint8_t doff : 4, res1 : 4;
#endif
        union {
            flags_type flags;
            uint8_t flags_8;
        };
        uint16_t window;
        uint16_t check;
        uint16_t urg_ptr;
    } __attribute__((packed));

    static const uint16_t DEFAULT_WINDOW;
    tcp_header header_;
};

} // namespace snet::net
